rule TTP_XOR_WriteProcessMemory_fc95 {
  strings:
    $key_fc95 = { ab e7 [2] 99 c5 [2] 9f f0 [2] b1 f0 [2] 8e ec }

  condition:
    any of them
}