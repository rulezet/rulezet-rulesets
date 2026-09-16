rule TTP_XOR_WriteProcessMemory_9d80 {
  strings:
    $key_9d80 = { ca f2 [2] f8 d0 [2] fe e5 [2] d0 e5 [2] ef f9 }

  condition:
    any of them
}