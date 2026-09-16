rule TTP_XOR_WriteProcessMemory_9de4 {
  strings:
    $key_9de4 = { ca 96 [2] f8 b4 [2] fe 81 [2] d0 81 [2] ef 9d }

  condition:
    any of them
}