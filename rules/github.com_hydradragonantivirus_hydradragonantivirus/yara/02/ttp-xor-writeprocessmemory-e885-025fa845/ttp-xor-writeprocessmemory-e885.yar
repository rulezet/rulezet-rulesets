rule TTP_XOR_WriteProcessMemory_e885 {
  strings:
    $key_e885 = { bf f7 [2] 8d d5 [2] 8b e0 [2] a5 e0 [2] 9a fc }

  condition:
    any of them
}