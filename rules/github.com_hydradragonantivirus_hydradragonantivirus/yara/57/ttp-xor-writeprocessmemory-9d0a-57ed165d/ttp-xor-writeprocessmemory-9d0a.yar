rule TTP_XOR_WriteProcessMemory_9d0a {
  strings:
    $key_9d0a = { ca 78 [2] f8 5a [2] fe 6f [2] d0 6f [2] ef 73 }

  condition:
    any of them
}