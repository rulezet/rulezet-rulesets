rule TTP_XOR_WriteProcessMemory_c201 {
  strings:
    $key_c201 = { 95 73 [2] a7 51 [2] a1 64 [2] 8f 64 [2] b0 78 }

  condition:
    any of them
}