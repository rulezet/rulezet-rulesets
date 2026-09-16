rule TTP_XOR_WriteProcessMemory_3f71 {
  strings:
    $key_3f71 = { 68 03 [2] 5a 21 [2] 5c 14 [2] 72 14 [2] 4d 08 }

  condition:
    any of them
}