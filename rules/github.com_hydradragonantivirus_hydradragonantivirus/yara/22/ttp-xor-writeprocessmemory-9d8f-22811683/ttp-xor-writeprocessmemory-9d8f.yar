rule TTP_XOR_WriteProcessMemory_9d8f {
  strings:
    $key_9d8f = { ca fd [2] f8 df [2] fe ea [2] d0 ea [2] ef f6 }

  condition:
    any of them
}