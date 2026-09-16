rule TTP_XOR_WriteProcessMemory_95f4 {
  strings:
    $key_95f4 = { c2 86 [2] f0 a4 [2] f6 91 [2] d8 91 [2] e7 8d }

  condition:
    any of them
}