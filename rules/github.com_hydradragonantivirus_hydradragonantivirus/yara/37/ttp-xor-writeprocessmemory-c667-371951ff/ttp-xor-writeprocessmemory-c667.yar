rule TTP_XOR_WriteProcessMemory_c667 {
  strings:
    $key_c667 = { 91 15 [2] a3 37 [2] a5 02 [2] 8b 02 [2] b4 1e }

  condition:
    any of them
}