rule TTP_XOR_WriteProcessMemory_9f82 {
  strings:
    $key_9f82 = { c8 f0 [2] fa d2 [2] fc e7 [2] d2 e7 [2] ed fb }

  condition:
    any of them
}