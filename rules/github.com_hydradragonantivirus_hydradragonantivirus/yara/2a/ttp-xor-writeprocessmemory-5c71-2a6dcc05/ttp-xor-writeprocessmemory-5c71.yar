rule TTP_XOR_WriteProcessMemory_5c71 {
  strings:
    $key_5c71 = { 0b 03 [2] 39 21 [2] 3f 14 [2] 11 14 [2] 2e 08 }

  condition:
    any of them
}