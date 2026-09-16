rule TTP_XOR_WriteProcessMemory_9c96 {
  strings:
    $key_9c96 = { cb e4 [2] f9 c6 [2] ff f3 [2] d1 f3 [2] ee ef }

  condition:
    any of them
}