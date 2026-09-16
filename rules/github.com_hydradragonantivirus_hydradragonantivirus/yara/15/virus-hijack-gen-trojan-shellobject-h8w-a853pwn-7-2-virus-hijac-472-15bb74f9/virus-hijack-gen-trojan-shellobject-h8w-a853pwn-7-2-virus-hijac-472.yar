rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_7_2_Virus_Hijac_472 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_13.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a853Pwn_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a853Pwn_2_2.vir, VirusShareTrojanClick257946_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c682e361f77ae05470a76065c7a3641d40a2707ab5bece61798a7542d7b48a04"
    hash2       = "9ab21b3b90a745ed3353a4d36c9a672433a2766d83aebcfbc91344ae184f2123"
    hash3       = "41d963d7c51619230bc56592a6e4d39c96e90c04d45292e87727f96761a16541"
    hash4       = "ab3d9cc812f93a0497e03ce65bf12058dc4bccb72d4c14d61e0b533f73a00ded"
    hash5       = "40a67ef952c61ca95324b6611b23fce774c422ef6bba33152eff55bd38488acc"
    hash6       = "774c11fe3a27eac0b4625398b65a1de4e7f3394087ad2330bc27345f36e390a2"
    hash7       = "f4a9429c26be601756d46b19c9e3f2916fa1968b2b1ec9658310e6db6bbccb55"
    hash8       = "54b03fbf5be7fa0ef285bf53401363c267bf23a2fde21c4a096d7d85078ccdd7"
    hash9       = "62a14b7a4498548b834b6e8b9fd51580efdfe695a3db8601a32229e4325a0732"
    hash10      = "2232141d329267f88679decd77f3992b67862e751aa2deaa6585cf8116eddeda"

  strings:
    $s1  = "# ~/.bash_profile: executed by bash(1) for login shells." fullword ascii
    $s2  = "# if [ -d \"${HOME}/bin\" ] ; then" fullword ascii
    $s3  = "# Set INFOPATH so it includes users' private info if it exists" fullword ascii
    $s4  = "# Set MANPATH so it includes users' private man if it exists" fullword ascii
    $s5  = "# if [ -d \"${HOME}/man\" ]; then" fullword ascii
    $s6  = "# if [ -d \"${HOME}/info\" ]; then" fullword ascii
    $s7  = "# source the users bashrc if it exists" fullword ascii
    $s8  = "# Set PATH so it includes user's private bin if it exists" fullword ascii
    $s9  = "if [ -f \"${HOME}/.bashrc\" ] ; then" fullword ascii
    $s10 = "# always be found at /etc/defaults/etc/skel/.bash_profile" fullword ascii
    $s11 = "# Modifying /etc/skel/.bash_profile directly will prevent" fullword ascii
    $s12 = "# User dependent .bash_profile file" fullword ascii
    $s13 = "# public domain worldwide. This software is distributed without any warranty. " fullword ascii
    $s14 = "# The copy in your home directory (~/.bash_profile) is yours, please" fullword ascii
    $s15 = "# copyright and related and neighboring rights to this software to the " fullword ascii
    $s16 = "# with this software. " fullword ascii
    $s17 = "# You should have received a copy of the CC0 Public Domain Dedication along " fullword ascii
    $s18 = "#   PATH=\"${HOME}/bin:${PATH}\"" fullword ascii
    $s19 = "  source \"${HOME}/.bashrc\"" fullword ascii
    $s20 = "#   MANPATH=\"${HOME}/man:${MANPATH}\"" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}