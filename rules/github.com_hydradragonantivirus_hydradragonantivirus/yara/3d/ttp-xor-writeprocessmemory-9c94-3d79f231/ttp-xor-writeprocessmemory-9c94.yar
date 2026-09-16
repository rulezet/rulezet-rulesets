rule TTP_XOR_WriteProcessMemory_9c94 {
  strings:
    $key_9c94 = { cb e6 [2] f9 c4 [2] ff f1 [2] d1 f1 [2] ee ed }

  condition:
    any of them
}