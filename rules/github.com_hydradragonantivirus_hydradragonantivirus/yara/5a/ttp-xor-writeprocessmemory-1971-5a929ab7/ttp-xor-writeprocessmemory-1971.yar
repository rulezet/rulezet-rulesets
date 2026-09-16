rule TTP_XOR_WriteProcessMemory_1971 {
  strings:
    $key_1971 = { 4e 03 [2] 7c 21 [2] 7a 14 [2] 54 14 [2] 6b 08 }

  condition:
    any of them
}