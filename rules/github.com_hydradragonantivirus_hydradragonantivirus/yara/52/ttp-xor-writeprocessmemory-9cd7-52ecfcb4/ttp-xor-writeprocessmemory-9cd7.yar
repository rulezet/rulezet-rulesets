rule TTP_XOR_WriteProcessMemory_9cd7 {
  strings:
    $key_9cd7 = { cb a5 [2] f9 87 [2] ff b2 [2] d1 b2 [2] ee ae }

  condition:
    any of them
}