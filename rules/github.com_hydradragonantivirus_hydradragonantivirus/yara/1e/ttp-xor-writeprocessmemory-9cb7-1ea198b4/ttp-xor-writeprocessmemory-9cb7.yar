rule TTP_XOR_WriteProcessMemory_9cb7 {
  strings:
    $key_9cb7 = { cb c5 [2] f9 e7 [2] ff d2 [2] d1 d2 [2] ee ce }

  condition:
    any of them
}