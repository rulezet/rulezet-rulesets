rule TTP_XOR_WriteProcessMemory_c525 {
  strings:
    $key_c525 = { 92 57 [2] a0 75 [2] a6 40 [2] 88 40 [2] b7 5c }

  condition:
    any of them
}