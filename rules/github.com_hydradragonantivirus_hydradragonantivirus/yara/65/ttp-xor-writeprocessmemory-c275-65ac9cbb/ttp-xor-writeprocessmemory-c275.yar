rule TTP_XOR_WriteProcessMemory_c275 {
  strings:
    $key_c275 = { 95 07 [2] a7 25 [2] a1 10 [2] 8f 10 [2] b0 0c }

  condition:
    any of them
}