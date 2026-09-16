rule TTP_XOR_WriteProcessMemory_9e8f {
  strings:
    $key_9e8f = { c9 fd [2] fb df [2] fd ea [2] d3 ea [2] ec f6 }

  condition:
    any of them
}