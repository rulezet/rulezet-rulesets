rule TTP_XOR_WriteProcessMemory_9c22 {
  strings:
    $key_9c22 = { cb 50 [2] f9 72 [2] ff 47 [2] d1 47 [2] ee 5b }

  condition:
    any of them
}