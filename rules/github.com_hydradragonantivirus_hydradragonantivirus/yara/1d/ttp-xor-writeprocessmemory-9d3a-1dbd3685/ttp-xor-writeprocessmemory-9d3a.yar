rule TTP_XOR_WriteProcessMemory_9d3a {
  strings:
    $key_9d3a = { ca 48 [2] f8 6a [2] fe 5f [2] d0 5f [2] ef 43 }

  condition:
    any of them
}