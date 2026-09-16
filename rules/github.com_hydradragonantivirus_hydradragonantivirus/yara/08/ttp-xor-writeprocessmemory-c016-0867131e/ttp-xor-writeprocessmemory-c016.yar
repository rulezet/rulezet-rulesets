rule TTP_XOR_WriteProcessMemory_c016 {
  strings:
    $key_c016 = { 97 64 [2] a5 46 [2] a3 73 [2] 8d 73 [2] b2 6f }

  condition:
    any of them
}