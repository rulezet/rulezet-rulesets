rule TTP_XOR_WriteProcessMemory_9d15 {
  strings:
    $key_9d15 = { ca 67 [2] f8 45 [2] fe 70 [2] d0 70 [2] ef 6c }

  condition:
    any of them
}