rule TTP_XOR_WriteProcessMemory_7006 {
  strings:
    $key_7006 = { 27 74 [2] 15 56 [2] 13 63 [2] 3d 63 [2] 02 7f }

  condition:
    any of them
}