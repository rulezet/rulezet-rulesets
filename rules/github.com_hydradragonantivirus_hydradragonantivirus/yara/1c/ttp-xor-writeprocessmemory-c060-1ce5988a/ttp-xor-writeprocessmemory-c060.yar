rule TTP_XOR_WriteProcessMemory_c060 {
  strings:
    $key_c060 = { 97 12 [2] a5 30 [2] a3 05 [2] 8d 05 [2] b2 19 }

  condition:
    any of them
}