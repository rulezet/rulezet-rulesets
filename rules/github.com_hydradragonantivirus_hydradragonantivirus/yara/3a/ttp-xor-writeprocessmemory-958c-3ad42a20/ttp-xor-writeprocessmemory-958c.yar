rule TTP_XOR_WriteProcessMemory_958c {
  strings:
    $key_958c = { c2 fe [2] f0 dc [2] f6 e9 [2] d8 e9 [2] e7 f5 }

  condition:
    any of them
}