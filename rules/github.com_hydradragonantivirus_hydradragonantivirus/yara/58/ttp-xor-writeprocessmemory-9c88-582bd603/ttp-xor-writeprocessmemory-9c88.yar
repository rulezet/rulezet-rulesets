rule TTP_XOR_WriteProcessMemory_9c88 {
  strings:
    $key_9c88 = { cb fa [2] f9 d8 [2] ff ed [2] d1 ed [2] ee f1 }

  condition:
    any of them
}