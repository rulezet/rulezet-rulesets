rule TTP_XOR_WriteProcessMemory_d64d {
  strings:
    $key_d64d = { 81 3f [2] b3 1d [2] b5 28 [2] 9b 28 [2] a4 34 }

  condition:
    any of them
}