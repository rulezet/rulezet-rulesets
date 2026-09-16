rule TTP_XOR_WriteProcessMemory_9c82 {
  strings:
    $key_9c82 = { cb f0 [2] f9 d2 [2] ff e7 [2] d1 e7 [2] ee fb }

  condition:
    any of them
}