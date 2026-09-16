rule TTP_XOR_WriteProcessMemory_9cd6 {
  strings:
    $key_9cd6 = { cb a4 [2] f9 86 [2] ff b3 [2] d1 b3 [2] ee af }

  condition:
    any of them
}