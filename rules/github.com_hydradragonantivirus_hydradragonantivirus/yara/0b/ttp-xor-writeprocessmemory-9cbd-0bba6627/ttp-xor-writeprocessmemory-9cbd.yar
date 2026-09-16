rule TTP_XOR_WriteProcessMemory_9cbd {
  strings:
    $key_9cbd = { cb cf [2] f9 ed [2] ff d8 [2] d1 d8 [2] ee c4 }

  condition:
    any of them
}