rule TTP_XOR_WriteProcessMemory_9c9b {
  strings:
    $key_9c9b = { cb e9 [2] f9 cb [2] ff fe [2] d1 fe [2] ee e2 }

  condition:
    any of them
}