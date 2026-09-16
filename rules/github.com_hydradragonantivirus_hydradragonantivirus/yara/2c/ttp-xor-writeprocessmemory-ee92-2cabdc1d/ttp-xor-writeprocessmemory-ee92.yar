rule TTP_XOR_WriteProcessMemory_ee92 {
  strings:
    $key_ee92 = { b9 e0 [2] 8b c2 [2] 8d f7 [2] a3 f7 [2] 9c eb }

  condition:
    any of them
}