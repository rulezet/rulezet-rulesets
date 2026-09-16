rule TTP_XOR_WriteProcessMemory_de27 {
  strings:
    $key_de27 = { 89 55 [2] bb 77 [2] bd 42 [2] 93 42 [2] ac 5e }

  condition:
    any of them
}