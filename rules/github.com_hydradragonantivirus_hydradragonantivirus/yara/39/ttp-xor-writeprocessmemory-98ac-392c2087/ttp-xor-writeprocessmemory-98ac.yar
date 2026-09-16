rule TTP_XOR_WriteProcessMemory_98ac {
  strings:
    $key_98ac = { cf de [2] fd fc [2] fb c9 [2] d5 c9 [2] ea d5 }

  condition:
    any of them
}