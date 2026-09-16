rule TTP_XOR_WriteProcessMemory_8a85 {
  strings:
    $key_8a85 = { dd f7 [2] ef d5 [2] e9 e0 [2] c7 e0 [2] f8 fc }

  condition:
    any of them
}