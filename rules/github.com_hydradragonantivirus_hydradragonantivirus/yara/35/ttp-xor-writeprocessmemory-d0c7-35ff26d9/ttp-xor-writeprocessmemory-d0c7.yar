rule TTP_XOR_WriteProcessMemory_d0c7 {
  strings:
    $key_d0c7 = { 87 b5 [2] b5 97 [2] b3 a2 [2] 9d a2 [2] a2 be }

  condition:
    any of them
}