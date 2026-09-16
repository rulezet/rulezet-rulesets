import "pe"
rule files_tmp {
  meta:
    description = "8099 - file tmp.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
    date        = "2021-12-12"
    hash1       = "493a1fbe833c419b37bb345f6f193517d5d9fd2577f09cc74b48b49d7d732a54"

  strings:
    $s1  = "UncategorizedOtherOutOfMemoryUnexpectedEofInterruptedArgumentListTooLongFilenameTooLongTooManyLinksCrossesDevicesDeadlockExecuta" ascii
    $s2  = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longfilename " ascii
    $s3  = "kuiiqaiusmlytqxxnrtl.dll" fullword ascii
    $s4  = "Node.js API crypto.randomFillSync is unavailableNode.js crypto module is unavailablerandSecure: VxWorks RNG module is not initia" ascii
    $s5  = "ctoryoperation would blockentity already existsbroken pipenetwork downaddress not availableaddress in usenot connectedconnection" ascii
    $s6  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s7  = "keyed events not availableC:rtzkoqhrehbskobagkzngetniywbivatkcfmkxxumjxevfohiuxtzrkjoopvcwassaovngxtdmzbhlhkgasumqlldyupsmjyztrd" ascii
    $s8  = "keyed events not availableC:rtzkoqhrehbskobagkzngetniywbivatkcfmkxxumjxevfohiuxtzrkjoopvcwassaovngxtdmzbhlhkgasumqlldyupsmjyztrd" ascii
    $s9  = "attempted to index slice from after maximum usizeattempted to index slice up to maximum usizeassertion failed: mid <= self.len()" ascii
    $s10 = "attempted to zero-initialize type `alloc::string::String`, which is invalidassertion failed: 0 < pointee_size && pointee_size <=" ascii
    $s11 = "attempted to zero-initialize type `&str`, which is invalidassertion failed: 0 < pointee_size && pointee_size <= isize::MAX as us" ascii
    $s12 = "attempted to zero-initialize type `&str`, which is invalidassertion failed: 0 < pointee_size && pointee_size <= isize::MAX as us" ascii
    $s13 = "rno: did not return a positive valuegetrandom: this target is not supportedC:ehpgbcedommleqfhulhfnkiqvffztwzvxtvorsmuwrtkmtsqdfl" ascii
    $s14 = "attempted to zero-initialize type `(*mut u8, unsafe extern \"C\" fn(*mut u8))`, which is invalidassertion failed: 0 < pointee_si" ascii
    $s15 = "attempted to index slice from after maximum usizeattempted to index slice up to maximum usizeassertion failed: mid <= self.len()" ascii
    $s16 = "attempted to zero-initialize type `alloc::string::String`, which is invalidassertion failed: 0 < pointee_size && pointee_size <=" ascii
    $s17 = "workFileHandleFilesystemLoopReadOnlyFilesystemDirectoryNotEmptyIsADirectoryNotADirectoryWouldBlockAlreadyExistsBrokenPipeNetwork" ascii
    $s18 = "abortednetwork unreachablehost unreachableconnection resetconnection refusedpermission deniedentity not foundErrorkind" fullword ascii
    $s19 = "thread panicked while processing panic. aborting." fullword ascii
    $s20 = "internal_codedescription0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and
    (pe.imphash() == "59e16a2afa5b682bb9692bac873fa10c" and (pe.exports("EnterDll") and pe.exports("alpjxriee") and pe.exports("arcfqsbobtwbjrf") and pe.exports("asblsmvdudmlwht") and pe.exports("bgttsajxwgwrsai") and pe.exports("bosaplw")) or 8 of them)
}