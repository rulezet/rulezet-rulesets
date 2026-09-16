rule TTP_XOR_WriteProcessMemory_b41f {
  strings:
    $key_b41f = { e3 6d [2] d1 4f [2] d7 7a [2] f9 7a [2] c6 66 }

  condition:
    any of them
}