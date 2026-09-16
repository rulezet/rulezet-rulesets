rule TTP_XOR_WriteProcessMemory_c022 {
  strings:
    $key_c022 = { 97 50 [2] a5 72 [2] a3 47 [2] 8d 47 [2] b2 5b }

  condition:
    any of them
}