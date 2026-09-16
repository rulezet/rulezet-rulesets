rule TTP_XOR_WriteProcessMemory_a7ea {
  strings:
    $key_a7ea = { f0 98 [2] c2 ba [2] c4 8f [2] ea 8f [2] d5 93 }

  condition:
    any of them
}