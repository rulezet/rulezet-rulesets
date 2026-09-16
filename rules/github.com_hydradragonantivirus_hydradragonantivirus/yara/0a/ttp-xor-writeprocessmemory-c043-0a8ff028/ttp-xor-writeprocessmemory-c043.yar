rule TTP_XOR_WriteProcessMemory_c043 {
  strings:
    $key_c043 = { 97 31 [2] a5 13 [2] a3 26 [2] 8d 26 [2] b2 3a }

  condition:
    any of them
}