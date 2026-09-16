rule TTP_XOR_WriteProcessMemory_8a99 {
  strings:
    $key_8a99 = { dd eb [2] ef c9 [2] e9 fc [2] c7 fc [2] f8 e0 }

  condition:
    any of them
}