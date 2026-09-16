rule TTP_XOR_WriteProcessMemory_8afd {
  strings:
    $key_8afd = { dd 8f [2] ef ad [2] e9 98 [2] c7 98 [2] f8 84 }

  condition:
    any of them
}