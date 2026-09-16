import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_auLSMIo_21_2_Virus_Hija_83 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_21_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_22_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c672b0b93ad76e1048b0f5845b869872ffac37c5f42f7f05b0dd08a0ddb688f1"
    hash2       = "074b41f8535ec8adf5ab5014783a7cd3140f5826c74ec324447941a7f2114ced"
    hash3       = "2df9c691b1b76356a24fcc18932642ed268a9ca94a3544cacadeed1e64d19a8a"
    hash4       = "f9db2f36f2f8ac450c76bf898abc67c84779cc7f186ba7c1e55893497c18f6e9"

  strings:
    $x1  = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii
    $x2  = "workbuf is empty initialHeapLive= spinningthreads=0123456789ABCDEFX0123456789abcdefx1192092895507812559604644775390625: missing " ascii
    $x3  = " to unallocated span37252902984619140625: leftover defer sp=Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreatePr" ascii
    $x4  = " > (den<<shift)/245474735088646411895751953125Central America Standard TimeCentral Pacific Standard TimeChatham Islands Standard" ascii
    $x5  = "unknown pcws2_32.dll  of size   (targetpc= gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing= ms clock" ascii
    $x6  = "stopTheWorld: not stopped (status != _Pgcstop)P has cached GC work at end of mark terminationattempting to link in too many shar" ascii
    $x7  = "Variation_Selectorbad lfnode addressbad manualFreeListconnection refusedfile name too longforEachP: not donegarbage collectionid" ascii
    $x8  = "Pakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeTasmania Standard Timeaddress already in useadvapi32.dll not f" ascii
    $x9  = " of unexported method previous allocCount=186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAn" ascii
    $x10 = "476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushVie" ascii
    $x11 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii
    $s12 = "structure needs cleaning bytes failed with errno= to unused region of span2910383045673370361328125AUS Central Standard TimeAUS " ascii
    $s13 = "shell32.dllshort writetracealloc(unreachableuserenv.dll [recovered] allocCount  found at *( gcscandone  m->gsignal= minTrigger= " ascii
    $s14 = "mstartbad value for fielddevice not a streamdirectory not emptydisk quota exceededfile already closedfile already existsfile doe" ascii
    $s15 = "entifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation canceledracy" ascii
    $s16 = "invalid pointer found on stacknode is not its parent's childnotetsleep - waitm out of syncprotocol wrong type for socketreflect:" ascii
    $s17 = "method C:\\Program Files\\DnsRecordListFreeFLE Standard TimeGC assist markingGMT Standard TimeGTB Standard TimeGetCurrentProcess" ascii
    $s18 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablelarge span treap" ascii
    $s19 = "CertEnumCertificatesInStoreEaster Island Standard TimeG waiting list is corruptedaddress not a stack addresschannel number out o" ascii
    $s20 = "sExWGetProcessMemoryInfoIDS_Trinary_OperatorIsrael Standard TimeJordan Standard TimeMeroitic_HieroglyphsSeek: invalid offsetSeek" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f0070935b15a909b9dc00be7997e6112" and (1 of ($x*) and all of them)
    ) or (all of them)
}