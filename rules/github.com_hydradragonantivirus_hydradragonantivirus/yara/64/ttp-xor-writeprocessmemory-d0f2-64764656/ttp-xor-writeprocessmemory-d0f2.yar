rule TTP_XOR_WriteProcessMemory_d0f2 {
  strings:
    $key_d0f2 = { 87 80 [2] b5 a2 [2] b3 97 [2] 9d 97 [2] a2 8b }

  condition:
    any of them
}