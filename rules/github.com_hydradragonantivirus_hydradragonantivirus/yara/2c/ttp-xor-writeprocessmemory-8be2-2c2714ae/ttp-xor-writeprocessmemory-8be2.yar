rule TTP_XOR_WriteProcessMemory_8be2 {
  strings:
    $key_8be2 = { dc 90 [2] ee b2 [2] e8 87 [2] c6 87 [2] f9 9b }

  condition:
    any of them
}