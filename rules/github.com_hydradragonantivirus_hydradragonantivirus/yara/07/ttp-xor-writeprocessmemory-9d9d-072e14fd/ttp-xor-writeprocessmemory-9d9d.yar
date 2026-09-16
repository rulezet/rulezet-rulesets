rule TTP_XOR_WriteProcessMemory_9d9d {
  strings:
    $key_9d9d = { ca ef [2] f8 cd [2] fe f8 [2] d0 f8 [2] ef e4 }

  condition:
    any of them
}