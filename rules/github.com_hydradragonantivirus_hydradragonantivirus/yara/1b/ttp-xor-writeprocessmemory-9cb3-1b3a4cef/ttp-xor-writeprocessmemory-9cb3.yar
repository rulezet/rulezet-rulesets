rule TTP_XOR_WriteProcessMemory_9cb3 {
  strings:
    $key_9cb3 = { cb c1 [2] f9 e3 [2] ff d6 [2] d1 d6 [2] ee ca }

  condition:
    any of them
}