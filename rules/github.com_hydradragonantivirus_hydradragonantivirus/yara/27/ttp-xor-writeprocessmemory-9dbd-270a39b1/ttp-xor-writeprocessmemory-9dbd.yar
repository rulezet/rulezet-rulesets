rule TTP_XOR_WriteProcessMemory_9dbd {
  strings:
    $key_9dbd = { ca cf [2] f8 ed [2] fe d8 [2] d0 d8 [2] ef c4 }

  condition:
    any of them
}