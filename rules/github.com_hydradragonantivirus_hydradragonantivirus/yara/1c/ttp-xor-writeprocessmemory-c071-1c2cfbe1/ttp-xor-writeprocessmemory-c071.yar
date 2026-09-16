rule TTP_XOR_WriteProcessMemory_c071 {
  strings:
    $key_c071 = { 97 03 [2] a5 21 [2] a3 14 [2] 8d 14 [2] b2 08 }

  condition:
    any of them
}