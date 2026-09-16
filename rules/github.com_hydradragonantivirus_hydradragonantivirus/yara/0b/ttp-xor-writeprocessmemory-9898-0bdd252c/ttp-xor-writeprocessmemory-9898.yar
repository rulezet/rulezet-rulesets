rule TTP_XOR_WriteProcessMemory_9898 {
  strings:
    $key_9898 = { cf ea [2] fd c8 [2] fb fd [2] d5 fd [2] ea e1 }

  condition:
    any of them
}