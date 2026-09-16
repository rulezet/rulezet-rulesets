rule TTP_XOR_WriteProcessMemory_c652 {
  strings:
    $key_c652 = { 91 20 [2] a3 02 [2] a5 37 [2] 8b 37 [2] b4 2b }

  condition:
    any of them
}