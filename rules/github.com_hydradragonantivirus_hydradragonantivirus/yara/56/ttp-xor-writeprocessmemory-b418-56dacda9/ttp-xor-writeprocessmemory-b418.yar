rule TTP_XOR_WriteProcessMemory_b418 {
  strings:
    $key_b418 = { e3 6a [2] d1 48 [2] d7 7d [2] f9 7d [2] c6 61 }

  condition:
    any of them
}