rule TTP_XOR_WriteProcessMemory_b468 {
  strings:
    $key_b468 = { e3 1a [2] d1 38 [2] d7 0d [2] f9 0d [2] c6 11 }

  condition:
    any of them
}