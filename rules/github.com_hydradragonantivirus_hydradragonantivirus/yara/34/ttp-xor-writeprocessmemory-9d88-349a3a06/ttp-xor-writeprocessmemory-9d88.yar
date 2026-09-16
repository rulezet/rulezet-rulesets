rule TTP_XOR_WriteProcessMemory_9d88 {
  strings:
    $key_9d88 = { ca fa [2] f8 d8 [2] fe ed [2] d0 ed [2] ef f1 }

  condition:
    any of them
}