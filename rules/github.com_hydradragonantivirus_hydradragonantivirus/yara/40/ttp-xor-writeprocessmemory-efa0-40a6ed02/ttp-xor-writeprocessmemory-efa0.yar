rule TTP_XOR_WriteProcessMemory_efa0 {
  strings:
    $key_efa0 = { b8 d2 [2] 8a f0 [2] 8c c5 [2] a2 c5 [2] 9d d9 }

  condition:
    any of them
}