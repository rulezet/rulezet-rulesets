rule TTP_XOR_WriteProcessMemory_9cb2 {
  strings:
    $key_9cb2 = { cb c0 [2] f9 e2 [2] ff d7 [2] d1 d7 [2] ee cb }

  condition:
    any of them
}