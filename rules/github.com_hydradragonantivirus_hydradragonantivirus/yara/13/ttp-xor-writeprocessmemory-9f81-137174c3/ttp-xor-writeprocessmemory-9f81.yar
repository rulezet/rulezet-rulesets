rule TTP_XOR_WriteProcessMemory_9f81 {
  strings:
    $key_9f81 = { c8 f3 [2] fa d1 [2] fc e4 [2] d2 e4 [2] ed f8 }

  condition:
    any of them
}