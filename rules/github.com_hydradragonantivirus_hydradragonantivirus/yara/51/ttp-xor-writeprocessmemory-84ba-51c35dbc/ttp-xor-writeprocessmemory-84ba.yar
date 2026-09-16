rule TTP_XOR_WriteProcessMemory_84ba {
  strings:
    $key_84ba = { d3 c8 [2] e1 ea [2] e7 df [2] c9 df [2] f6 c3 }

  condition:
    any of them
}