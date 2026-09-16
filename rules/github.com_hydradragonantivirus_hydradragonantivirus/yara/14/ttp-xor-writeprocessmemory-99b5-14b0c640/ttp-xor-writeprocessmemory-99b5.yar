rule TTP_XOR_WriteProcessMemory_99b5 {
  strings:
    $key_99b5 = { ce c7 [2] fc e5 [2] fa d0 [2] d4 d0 [2] eb cc }

  condition:
    any of them
}