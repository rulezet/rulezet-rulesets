rule TTP_XOR_WriteProcessMemory_e880 {
  strings:
    $key_e880 = { bf f2 [2] 8d d0 [2] 8b e5 [2] a5 e5 [2] 9a f9 }

  condition:
    any of them
}