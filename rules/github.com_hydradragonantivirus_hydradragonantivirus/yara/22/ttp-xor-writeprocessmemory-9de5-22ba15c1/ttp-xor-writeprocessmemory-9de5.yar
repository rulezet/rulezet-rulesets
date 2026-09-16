rule TTP_XOR_WriteProcessMemory_9de5 {
  strings:
    $key_9de5 = { ca 97 [2] f8 b5 [2] fe 80 [2] d0 80 [2] ef 9c }

  condition:
    any of them
}