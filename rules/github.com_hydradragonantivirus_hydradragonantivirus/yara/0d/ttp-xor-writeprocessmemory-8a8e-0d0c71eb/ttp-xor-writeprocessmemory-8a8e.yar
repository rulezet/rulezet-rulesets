rule TTP_XOR_WriteProcessMemory_8a8e {
  strings:
    $key_8a8e = { dd fc [2] ef de [2] e9 eb [2] c7 eb [2] f8 f7 }

  condition:
    any of them
}