rule TTP_XOR_WriteProcessMemory_d43d {
  strings:
    $key_d43d = { 83 4f [2] b1 6d [2] b7 58 [2] 99 58 [2] a6 44 }

  condition:
    any of them
}