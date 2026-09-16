rule TTP_XOR_WriteProcessMemory_9ded {
  strings:
    $key_9ded = { ca 9f [2] f8 bd [2] fe 88 [2] d0 88 [2] ef 94 }

  condition:
    any of them
}