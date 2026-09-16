rule TTP_XOR_WriteProcessMemory_c0c7 {
  strings:
    $key_c0c7 = { 97 b5 [2] a5 97 [2] a3 a2 [2] 8d a2 [2] b2 be }

  condition:
    any of them
}