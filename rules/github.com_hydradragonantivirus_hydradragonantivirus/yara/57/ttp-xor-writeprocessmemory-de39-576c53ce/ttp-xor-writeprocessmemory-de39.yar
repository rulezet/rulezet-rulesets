rule TTP_XOR_WriteProcessMemory_de39 {
  strings:
    $key_de39 = { 89 4b [2] bb 69 [2] bd 5c [2] 93 5c [2] ac 40 }

  condition:
    any of them
}