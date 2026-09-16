rule TTP_XOR_WriteProcessMemory_9da8 {
  strings:
    $key_9da8 = { ca da [2] f8 f8 [2] fe cd [2] d0 cd [2] ef d1 }

  condition:
    any of them
}