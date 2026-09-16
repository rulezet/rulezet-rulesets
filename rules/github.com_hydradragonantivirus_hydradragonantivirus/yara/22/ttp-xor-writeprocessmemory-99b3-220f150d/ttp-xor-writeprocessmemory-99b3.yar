rule TTP_XOR_WriteProcessMemory_99b3 {
  strings:
    $key_99b3 = { ce c1 [2] fc e3 [2] fa d6 [2] d4 d6 [2] eb ca }

  condition:
    any of them
}