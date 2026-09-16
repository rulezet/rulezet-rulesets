rule TTP_XOR_WriteProcessMemory_9ddd {
  strings:
    $key_9ddd = { ca af [2] f8 8d [2] fe b8 [2] d0 b8 [2] ef a4 }

  condition:
    any of them
}