rule TTP_XOR_WriteProcessMemory_9dc7 {
  strings:
    $key_9dc7 = { ca b5 [2] f8 97 [2] fe a2 [2] d0 a2 [2] ef be }

  condition:
    any of them
}