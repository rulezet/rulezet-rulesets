rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_1_2_Virus_Hijac_272 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a853Pwn_2_2.vir, VirusShareTrojanClick257946_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb6504dce35506f80863be6da7874cff81a8c5544322f1e8cd4e050132fc641d"
    hash2       = "cea0f6579e0a9fc4f65c6d764a391e16713718b2ae8f9d02ec0b5aab0052f275"
    hash3       = "fcfa5783774e74956d95e0deedf9d25babe25559d2ba4e81addbda1b4a626f52"
    hash4       = "805467295987f3519bf932175cd11417a79a8ea52d2bd0680f11d966cb7a1049"
    hash5       = "39bb2cb891205f1e07366c1cbcffb9c4e02298929b19cb8544e10f0ae7341199"
    hash6       = "adad97a7238ac911d1656947903a0b7bfff1e2e4180e5dff303b20914352c977"
    hash7       = "874c2e6f552ddd05c4a2f51a7859422bdb36992ab31f92480f15a355eaf799f8"
    hash8       = "62a14b7a4498548b834b6e8b9fd51580efdfe695a3db8601a32229e4325a0732"
    hash9       = "2232141d329267f88679decd77f3992b67862e751aa2deaa6585cf8116eddeda"

  strings:
    $s1  = "# The bug address depends on the release status of the shell.  Versions" fullword ascii
    $s2  = "# bashbug - create a bug report and mail it to the bug address" fullword ascii
    $s3  = "elif [ -x /usr/bin/xemacs ]; then" fullword ascii
    $s4  = "# Check if TMPDIR is set, default to /tmp" fullword ascii
    $s5  = "trap 'rm -rf \"$TEMPDIR\"; exit 1' 1 2 3 13 15" fullword ascii
    $s6  = "if [ -z \"$DEFEDITOR\" ] && [ -z \"$EDITOR\" ]; then" fullword ascii
    $s7  = "# find the subject from the temp file and see if it's been changed" fullword ascii
    $s8  = "elif [ -x /usr/bin/vi ]; then" fullword ascii
    $s9  = "USAGE=\"Usage: $0 [--help] [--version] [bug-report-email-address]\"" fullword ascii
    $s10 = "elif [ -f /usr/sbin/sendmail ] ; then" fullword ascii
    $s11 = "echo \"$0: Please use a more descriptive subject header.\"" fullword ascii
    $s12 = "trap 'rm -rf \"$TEMPDIR\"' 0" fullword ascii
    $s13 = "trap 'rm -rf \"$TEMPDIR\"; exit 1' 2" fullword ascii
    $s14 = "elif [ -x /usr/contrib/bin/jove ]; then" fullword ascii
    $s15 = "elif [ -x /usr/contrib/bin/emacs ]; then" fullword ascii
    $s16 = "if [ -x /usr/bin/editor ]; then" fullword ascii
    $s17 = "if [ -n \"$do_version\" ]; then" fullword ascii
    $s18 = "elif [ -x /usr/bin/emacs ]; then" fullword ascii
    $s19 = "template for you to fill in. The report will be mailed to the" fullword ascii
    $s20 = "# Other versions send mail to bug-bash@gnu.org." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}