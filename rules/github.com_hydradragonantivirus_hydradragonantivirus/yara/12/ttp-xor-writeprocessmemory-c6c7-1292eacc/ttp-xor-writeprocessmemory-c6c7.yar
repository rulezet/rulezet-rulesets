rule TTP_XOR_WriteProcessMemory_c6c7 {
  strings:
    $key_c6c7 = { 91 b5 [2] a3 97 [2] a5 a2 [2] 8b a2 [2] b4 be }

  condition:
    any of them
}