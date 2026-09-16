rule TTP_XOR_WriteProcessMemory_c665 {
  strings:
    $key_c665 = { 91 17 [2] a3 35 [2] a5 00 [2] 8b 00 [2] b4 1c }

  condition:
    any of them
}