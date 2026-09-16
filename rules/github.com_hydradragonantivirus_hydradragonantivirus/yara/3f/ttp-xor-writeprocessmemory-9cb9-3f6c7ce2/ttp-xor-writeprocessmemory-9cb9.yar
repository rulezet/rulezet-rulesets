rule TTP_XOR_WriteProcessMemory_9cb9 {
  strings:
    $key_9cb9 = { cb cb [2] f9 e9 [2] ff dc [2] d1 dc [2] ee c0 }

  condition:
    any of them
}