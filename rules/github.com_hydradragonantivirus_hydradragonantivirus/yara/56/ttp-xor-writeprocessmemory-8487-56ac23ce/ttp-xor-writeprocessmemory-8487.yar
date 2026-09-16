rule TTP_XOR_WriteProcessMemory_8487 {
  strings:
    $key_8487 = { d3 f5 [2] e1 d7 [2] e7 e2 [2] c9 e2 [2] f6 fe }

  condition:
    any of them
}