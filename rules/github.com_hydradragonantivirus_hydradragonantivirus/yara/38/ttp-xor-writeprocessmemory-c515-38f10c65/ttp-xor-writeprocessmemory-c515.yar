rule TTP_XOR_WriteProcessMemory_c515 {
  strings:
    $key_c515 = { 92 67 [2] a0 45 [2] a6 70 [2] 88 70 [2] b7 6c }

  condition:
    any of them
}