rule TTP_XOR_WriteProcessMemory_1de2 {
  strings:
    $key_1de2 = { 4a 90 [2] 78 b2 [2] 7e 87 [2] 50 87 [2] 6f 9b }

  condition:
    any of them
}