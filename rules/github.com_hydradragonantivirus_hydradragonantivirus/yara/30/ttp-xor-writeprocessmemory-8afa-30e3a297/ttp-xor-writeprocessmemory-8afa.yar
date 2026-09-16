rule TTP_XOR_WriteProcessMemory_8afa {
  strings:
    $key_8afa = { dd 88 [2] ef aa [2] e9 9f [2] c7 9f [2] f8 83 }

  condition:
    any of them
}