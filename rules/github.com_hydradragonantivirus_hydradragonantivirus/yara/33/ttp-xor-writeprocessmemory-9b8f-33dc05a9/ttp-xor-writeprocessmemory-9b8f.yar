rule TTP_XOR_WriteProcessMemory_9b8f {
  strings:
    $key_9b8f = { cc fd [2] fe df [2] f8 ea [2] d6 ea [2] e9 f6 }

  condition:
    any of them
}