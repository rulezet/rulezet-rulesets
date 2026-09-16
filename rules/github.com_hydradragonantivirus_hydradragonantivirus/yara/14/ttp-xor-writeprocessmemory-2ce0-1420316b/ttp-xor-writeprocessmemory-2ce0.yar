rule TTP_XOR_WriteProcessMemory_2ce0 {
  strings:
    $key_2ce0 = { 7b 92 [2] 49 b0 [2] 4f 85 [2] 61 85 [2] 5e 99 }

  condition:
    any of them
}