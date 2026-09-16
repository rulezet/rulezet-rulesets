rule TTP_XOR_WriteProcessMemory_9cb0 {
  strings:
    $key_9cb0 = { cb c2 [2] f9 e0 [2] ff d5 [2] d1 d5 [2] ee c9 }

  condition:
    any of them
}