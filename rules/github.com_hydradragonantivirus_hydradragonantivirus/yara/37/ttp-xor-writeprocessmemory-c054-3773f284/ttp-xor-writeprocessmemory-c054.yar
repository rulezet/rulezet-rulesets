rule TTP_XOR_WriteProcessMemory_c054 {
  strings:
    $key_c054 = { 97 26 [2] a5 04 [2] a3 31 [2] 8d 31 [2] b2 2d }

  condition:
    any of them
}