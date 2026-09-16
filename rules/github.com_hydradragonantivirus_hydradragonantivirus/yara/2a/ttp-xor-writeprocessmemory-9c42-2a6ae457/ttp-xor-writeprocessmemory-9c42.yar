rule TTP_XOR_WriteProcessMemory_9c42 {
  strings:
    $key_9c42 = { cb 30 [2] f9 12 [2] ff 27 [2] d1 27 [2] ee 3b }

  condition:
    any of them
}