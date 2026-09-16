rule TTP_XOR_WriteProcessMemory_9c91 {
  strings:
    $key_9c91 = { cb e3 [2] f9 c1 [2] ff f4 [2] d1 f4 [2] ee e8 }

  condition:
    any of them
}