rule TTP_XOR_WriteProcessMemory_93f4 {
  strings:
    $key_93f4 = { c4 86 [2] f6 a4 [2] f0 91 [2] de 91 [2] e1 8d }

  condition:
    any of them
}