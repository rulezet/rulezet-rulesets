rule TTP_XOR_WriteProcessMemory_c673 {
  strings:
    $key_c673 = { 91 01 [2] a3 23 [2] a5 16 [2] 8b 16 [2] b4 0a }

  condition:
    any of them
}