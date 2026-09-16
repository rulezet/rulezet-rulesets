rule TTP_XOR_WriteProcessMemory_ee80 {
  strings:
    $key_ee80 = { b9 f2 [2] 8b d0 [2] 8d e5 [2] a3 e5 [2] 9c f9 }

  condition:
    any of them
}