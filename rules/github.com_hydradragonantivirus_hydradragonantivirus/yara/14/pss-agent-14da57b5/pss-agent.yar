rule PSS_Agent {
  meta:
    description = "PSS Agent versions 4.x and 5.x"
    author      = "Geoffrey Alexander <geoff@citizenlab.ca>"
    date        = "2017-07-20"

  strings:
    $cmdproc = "CmdProc_" wide

    $u1 = "SS_Agent" ascii
    $u2 = "pss-agent" ascii
    $u3 = "DC615DA9-94B5-4477-9C33-3A393BC9E63F" ascii
    $u4 = { 06 1f 41 49 4d 48 50 4f 31 }

    $s1  = "util::Process::" ascii
    $s2  = "util::Resource::" ascii
    $s3  = "util::System::" ascii
    $s4  = "/M:{0FA12518-0120-0910-A43C-0DAA276D2EA4}" wide
    $s5  = "Command is not allowed due to potential detection threat: %1%." wide
    $s6  = "(%d) %.64s\\%.64s\\%.64s|%.64s|%.64s|%.64s|%.64s|%.64s|%.64s" wide
    $s7  = "Name: %s Due: %02d/%02d/%04d %02d:%02d:%02d, Length: %d seconds" wide
    $s8  = "Image will be taken on the next Skype call session." wide
    $s9  = "\\\\.\\pipe\\BrowseIPC" wide
    $s10 = "RES_BINARY" wide
    $s11 = "/{433a-bbaf439-12982d4a-9c27}" wide

  condition:
    uint16(0) == 0x5a4d and $cmdproc and 1 of ($u*) and 4 of ($s*)
}