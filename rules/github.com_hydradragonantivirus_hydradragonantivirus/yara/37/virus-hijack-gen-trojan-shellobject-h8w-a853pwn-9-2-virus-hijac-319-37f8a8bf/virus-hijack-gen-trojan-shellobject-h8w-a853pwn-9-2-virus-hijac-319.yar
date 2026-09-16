rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_9_2_Virus_Hijac_319 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a853Pwn_2_2.vir, VirusShareTrojanClick257946_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ab21b3b90a745ed3353a4d36c9a672433a2766d83aebcfbc91344ae184f2123"
    hash2       = "9e68803ee118256c8a1729b7d1f0b761ccdfd50cff611cfcd9d98f879a15410e"
    hash3       = "cea0f6579e0a9fc4f65c6d764a391e16713718b2ae8f9d02ec0b5aab0052f275"
    hash4       = "64d877c8985bce6cf68247548555db3628547393c883e98cbb4c7262c904aa24"
    hash5       = "fcfa5783774e74956d95e0deedf9d25babe25559d2ba4e81addbda1b4a626f52"
    hash6       = "7302e964793f853740b92325b2308b5537a880881a4acd99e6cb5ffbddc300ae"
    hash7       = "6ae945d9454e7c28385aa815b66e1fb51ef97fe11478e18426b316f45d20a3d6"
    hash8       = "6c370604b5ca0e249cd91085b6ef0b3b7814e99151565d00bf2859b29ad4637e"
    hash9       = "5336a38be33b2f8f6afba2ca60483c7b17e16565f5b073d2e712f96a104c626e"
    hash10      = "0c3087201b875290716203109c116aa67092952b7b0b983ca0414fc95c913c6e"
    hash11      = "d470656d006564f0f5d23c44f21c3633a8eb677c2906888e48b52df716020f64"
    hash12      = "fc08f422e4679b557dcc2c34468c4ef2df0ad33aa3b96e249cf098fae94167ff"
    hash13      = "3c0e62668297340d7c921f31ff8b93aef4045fd8451e2ed1af51487b4b840a0b"
    hash14      = "e25748fc0a21f5828cad702244731a582eb13e87950adadf0ac99906d769edb3"
    hash15      = "774c11fe3a27eac0b4625398b65a1de4e7f3394087ad2330bc27345f36e390a2"
    hash16      = "59410b9fcb6dfbc62f5fa8a5bc2d7d98d992230a3b67585794aa57fde692f7e1"
    hash17      = "12ee7d854db5ab4ed51117aba115e75b258f54aff30972d7718f7502316d8a0f"
    hash18      = "22fa522d7bb7644a76f58332a41943de55772ce9aeb4935923362498816bfc91"
    hash19      = "62a14b7a4498548b834b6e8b9fd51580efdfe695a3db8601a32229e4325a0732"
    hash20      = "2232141d329267f88679decd77f3992b67862e751aa2deaa6585cf8116eddeda"

  strings:
    $s1  = "# ~/.bashrc: executed by bash(1) for interactive shells." fullword ascii
    $s2  = "# Petar Marinov, http:/geocities.com/h2428, this is public domain" fullword ascii
    $s3  = "# export PROMPT_COMMAND=\"history -a\"" fullword ascii
    $s4  = "# export HISTIGNORE=$'[ \\t]*:&:[fb]g:exit:ls' # Ignore the ls command as well" fullword ascii
    $s5  = "# for example, cd /vr/lgo/apaache would find /var/log/apache" fullword ascii
    $s6  = "# if [ -f \"${HOME}/.bash_aliases\" ]; then" fullword ascii
    $s7  = "# Set a more restrictive umask: i.e. no exec perms for others:" fullword ascii
    $s8  = "# if [ -f \"${HOME}/.bash_functions\" ]; then" fullword ascii
    $s9  = "# Shell Options" fullword ascii
    $s10 = "# /etc/profile sets 022, removing write perms to group + others." fullword ascii
    $s11 = "# To use it, uncomment it, source this file and try 'cd --'." fullword ascii
    $s12 = "# /etc/profile.d/bash_completion.sh when the package bash_completetion" fullword ascii
    $s13 = "#     [[ -z $index ]] && index=1" fullword ascii
    $s14 = "#     [[ -z $adir ]] && return 1" fullword ascii
    $s15 = "# set -o notify" fullword ascii
    $s16 = "# Modifying /etc/skel/.bashrc directly will prevent" fullword ascii
    $s17 = "# they may mask.  For example, alias rm='rm -i' will mask the rm" fullword ascii
    $s18 = "# alias df='df -h'" fullword ascii
    $s19 = "# alias rm='rm -i'" fullword ascii
    $s20 = "# alias cp='cp -i'" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}