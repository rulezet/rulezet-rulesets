rule TTP_XOR_WriteProcessMemory_c042 {
  strings:
    $key_c042 = { 97 30 [2] a5 12 [2] a3 27 [2] 8d 27 [2] b2 3b }

  condition:
    any of them
}