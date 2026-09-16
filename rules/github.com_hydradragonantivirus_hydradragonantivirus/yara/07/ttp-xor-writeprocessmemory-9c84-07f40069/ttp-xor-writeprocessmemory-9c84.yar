rule TTP_XOR_WriteProcessMemory_9c84 {
  strings:
    $key_9c84 = { cb f6 [2] f9 d4 [2] ff e1 [2] d1 e1 [2] ee fd }

  condition:
    any of them
}