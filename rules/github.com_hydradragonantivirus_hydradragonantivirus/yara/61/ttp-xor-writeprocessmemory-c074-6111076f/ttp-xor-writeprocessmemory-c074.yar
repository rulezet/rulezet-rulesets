rule TTP_XOR_WriteProcessMemory_c074 {
  strings:
    $key_c074 = { 97 06 [2] a5 24 [2] a3 11 [2] 8d 11 [2] b2 0d }

  condition:
    any of them
}