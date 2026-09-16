rule TTP_XOR_WriteProcessMemory_4871 {
  strings:
    $key_4871 = { 1f 03 [2] 2d 21 [2] 2b 14 [2] 05 14 [2] 3a 08 }

  condition:
    any of them
}