rule TTP_XOR_WriteProcessMemory_c251 {
  strings:
    $key_c251 = { 95 23 [2] a7 01 [2] a1 34 [2] 8f 34 [2] b0 28 }

  condition:
    any of them
}