rule TTP_XOR_WriteProcessMemory_c007 {
  strings:
    $key_c007 = { 97 75 [2] a5 57 [2] a3 62 [2] 8d 62 [2] b2 7e }

  condition:
    any of them
}