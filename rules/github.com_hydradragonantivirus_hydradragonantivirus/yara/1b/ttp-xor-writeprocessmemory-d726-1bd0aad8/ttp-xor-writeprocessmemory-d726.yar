rule TTP_XOR_WriteProcessMemory_d726 {
  strings:
    $key_d726 = { 80 54 [2] b2 76 [2] b4 43 [2] 9a 43 [2] a5 5f }

  condition:
    any of them
}