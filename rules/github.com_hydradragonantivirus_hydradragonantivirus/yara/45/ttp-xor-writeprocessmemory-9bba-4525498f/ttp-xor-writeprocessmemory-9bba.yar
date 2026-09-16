rule TTP_XOR_WriteProcessMemory_9bba {
  strings:
    $key_9bba = { cc c8 [2] fe ea [2] f8 df [2] d6 df [2] e9 c3 }

  condition:
    any of them
}