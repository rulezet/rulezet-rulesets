rule TTP_XOR_WriteProcessMemory_99b2 {
  strings:
    $key_99b2 = { ce c0 [2] fc e2 [2] fa d7 [2] d4 d7 [2] eb cb }

  condition:
    any of them
}