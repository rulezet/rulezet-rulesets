rule TTP_XOR_WriteProcessMemory_c677 {
  strings:
    $key_c677 = { 91 05 [2] a3 27 [2] a5 12 [2] 8b 12 [2] b4 0e }

  condition:
    any of them
}