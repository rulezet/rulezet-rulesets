rule TTP_XOR_WriteProcessMemory_3a44 {
  strings:
    $key_3a44 = { 6d 36 [2] 5f 14 [2] 59 21 [2] 77 21 [2] 48 3d }

  condition:
    any of them
}