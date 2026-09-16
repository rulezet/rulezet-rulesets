rule TTP_XOR_WriteProcessMemory_9d85 {
  strings:
    $key_9d85 = { ca f7 [2] f8 d5 [2] fe e0 [2] d0 e0 [2] ef fc }

  condition:
    any of them
}