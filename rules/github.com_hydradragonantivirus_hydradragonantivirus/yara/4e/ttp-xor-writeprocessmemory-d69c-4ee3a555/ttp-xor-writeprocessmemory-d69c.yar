rule TTP_XOR_WriteProcessMemory_d69c {
  strings:
    $key_d69c = { 81 ee [2] b3 cc [2] b5 f9 [2] 9b f9 [2] a4 e5 }

  condition:
    any of them
}