rule TTP_XOR_WriteProcessMemory_9f92 {
  strings:
    $key_9f92 = { c8 e0 [2] fa c2 [2] fc f7 [2] d2 f7 [2] ed eb }

  condition:
    any of them
}