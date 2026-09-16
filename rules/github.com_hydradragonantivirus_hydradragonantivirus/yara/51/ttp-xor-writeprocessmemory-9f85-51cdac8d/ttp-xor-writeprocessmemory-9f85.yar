rule TTP_XOR_WriteProcessMemory_9f85 {
  strings:
    $key_9f85 = { c8 f7 [2] fa d5 [2] fc e0 [2] d2 e0 [2] ed fc }

  condition:
    any of them
}