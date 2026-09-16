rule TTP_XOR_WriteProcessMemory_9bbe {
  strings:
    $key_9bbe = { cc cc [2] fe ee [2] f8 db [2] d6 db [2] e9 c7 }

  condition:
    any of them
}