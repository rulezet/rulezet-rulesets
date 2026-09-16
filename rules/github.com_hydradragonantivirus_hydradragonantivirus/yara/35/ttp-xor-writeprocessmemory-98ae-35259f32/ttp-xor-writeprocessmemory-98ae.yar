rule TTP_XOR_WriteProcessMemory_98ae {
  strings:
    $key_98ae = { cf dc [2] fd fe [2] fb cb [2] d5 cb [2] ea d7 }

  condition:
    any of them
}