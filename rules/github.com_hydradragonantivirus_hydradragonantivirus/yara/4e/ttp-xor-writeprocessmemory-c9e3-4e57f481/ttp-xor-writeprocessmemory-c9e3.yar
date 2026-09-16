rule TTP_XOR_WriteProcessMemory_c9e3 {
  strings:
    $key_c9e3 = { 9e 91 [2] ac b3 [2] aa 86 [2] 84 86 [2] bb 9a }

  condition:
    any of them
}