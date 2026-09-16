rule TTP_XOR_WriteProcessMemory_8b87 {
  strings:
    $key_8b87 = { dc f5 [2] ee d7 [2] e8 e2 [2] c6 e2 [2] f9 fe }

  condition:
    any of them
}