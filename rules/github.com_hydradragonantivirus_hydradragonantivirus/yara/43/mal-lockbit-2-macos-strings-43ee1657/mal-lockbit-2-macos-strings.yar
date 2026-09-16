rule MAL_Lockbit_2_macOS_strings {
  meta:
    description   = "Matches strings found in Lockbit ransomware macOS sample."
    last_modified = "2024-01-18"
    author        = "@petermstewart"
    DaysofYara    = "18/100"
    sha256        = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"

  strings:
    $a1 = "lockbit"
    $a2 = "restore-my-files.txt"
    $a3 = "_I_need_to_bypass_this_"
    $a4 = "kLibsodiumDRG"
    $b  = "_Restore_My_Files_"

  condition:
    filesize < 500KB and
    (uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca) and      #b > 4 and
    all of ($a*)
}