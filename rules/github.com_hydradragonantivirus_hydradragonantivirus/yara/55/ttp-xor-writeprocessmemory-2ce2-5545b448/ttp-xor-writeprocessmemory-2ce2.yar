rule TTP_XOR_WriteProcessMemory_2ce2 {
  strings:
    $key_2ce2 = { 7b 90 [2] 49 b2 [2] 4f 87 [2] 61 87 [2] 5e 9b }

  condition:
    any of them
}