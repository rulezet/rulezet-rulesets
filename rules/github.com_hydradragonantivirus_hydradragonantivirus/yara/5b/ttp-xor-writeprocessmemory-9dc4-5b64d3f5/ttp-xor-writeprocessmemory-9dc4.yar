rule TTP_XOR_WriteProcessMemory_9dc4 {
  strings:
    $key_9dc4 = { ca b6 [2] f8 94 [2] fe a1 [2] d0 a1 [2] ef bd }

  condition:
    any of them
}