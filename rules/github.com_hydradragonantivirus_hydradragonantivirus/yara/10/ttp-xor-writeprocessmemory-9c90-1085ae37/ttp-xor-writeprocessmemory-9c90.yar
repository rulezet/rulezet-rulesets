rule TTP_XOR_WriteProcessMemory_9c90 {
  strings:
    $key_9c90 = { cb e2 [2] f9 c0 [2] ff f5 [2] d1 f5 [2] ee e9 }

  condition:
    any of them
}