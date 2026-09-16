rule TTP_XOR_WriteProcessMemory_1f71 {
  strings:
    $key_1f71 = { 48 03 [2] 7a 21 [2] 7c 14 [2] 52 14 [2] 6d 08 }

  condition:
    any of them
}