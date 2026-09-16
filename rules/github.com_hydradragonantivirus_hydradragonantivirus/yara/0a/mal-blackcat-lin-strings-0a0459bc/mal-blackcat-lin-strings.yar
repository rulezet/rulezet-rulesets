rule MAL_BlackCat_Lin_strings {
  meta:
    description   = "Matches strings found in BlackCat ransomware Linux samples operated by ALPHV"
    last_modified = "2024-01-15"
    author        = "@petermstewart"
    DaysofYara    = "15/100"
    sha256        = "3a08e3bfec2db5dbece359ac9662e65361a8625a0122e68b56cd5ef3aedf8ce1"
    sha256        = "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6"

  strings:
    $a1 = "encrypt_app::linux"
    $a2 = "src/bin/encrypt_app/linux.rs"
    $a3 = "locker::core::os::linux::command"
    $b1 = "note_file_name"
    $b2 = "note_full_text"
    $b3 = "note_short_text"
    $b4 = "default_file_cipher"
    $b5 = "default_file_mode"
    $b6 = "enable_esxi_vm_kill"
    $b7 = "enable_esxi_vm_snapshot_kill"

  condition:
    filesize > 1MB and filesize < 3MB and
    uint32(0) == 0x464c457f and
    2 of ($a*) and
    5 of ($b*)
}