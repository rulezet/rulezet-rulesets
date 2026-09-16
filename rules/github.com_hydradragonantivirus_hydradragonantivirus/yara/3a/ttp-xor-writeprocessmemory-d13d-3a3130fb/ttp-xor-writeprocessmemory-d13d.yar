rule TTP_XOR_WriteProcessMemory_d13d {
  strings:
    $key_d13d = { 86 4f [2] b4 6d [2] b2 58 [2] 9c 58 [2] a3 44 }

  condition:
    any of them
}