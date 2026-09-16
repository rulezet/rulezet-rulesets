rule TTP_XOR_WriteProcessMemory_6020 {
  strings:
    $key_6020 = { 37 52 [2] 05 70 [2] 03 45 [2] 2d 45 [2] 12 59 }

  condition:
    any of them
}