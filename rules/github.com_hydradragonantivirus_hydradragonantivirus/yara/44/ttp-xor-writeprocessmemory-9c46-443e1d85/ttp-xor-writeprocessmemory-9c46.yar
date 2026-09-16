rule TTP_XOR_WriteProcessMemory_9c46 {
  strings:
    $key_9c46 = { cb 34 [2] f9 16 [2] ff 23 [2] d1 23 [2] ee 3f }

  condition:
    any of them
}