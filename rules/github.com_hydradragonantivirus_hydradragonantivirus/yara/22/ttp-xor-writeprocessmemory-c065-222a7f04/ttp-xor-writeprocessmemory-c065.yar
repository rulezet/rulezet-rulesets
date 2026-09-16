rule TTP_XOR_WriteProcessMemory_c065 {
  strings:
    $key_c065 = { 97 17 [2] a5 35 [2] a3 00 [2] 8d 00 [2] b2 1c }

  condition:
    any of them
}