rule TTP_XOR_WriteProcessMemory_b478 {
  strings:
    $key_b478 = { e3 0a [2] d1 28 [2] d7 1d [2] f9 1d [2] c6 01 }

  condition:
    any of them
}