rule TTP_XOR_WriteProcessMemory_de57 {
  strings:
    $key_de57 = { 89 25 [2] bb 07 [2] bd 32 [2] 93 32 [2] ac 2e }

  condition:
    any of them
}