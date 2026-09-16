rule TTP_XOR_WriteProcessMemory_9c66 {
  strings:
    $key_9c66 = { cb 14 [2] f9 36 [2] ff 03 [2] d1 03 [2] ee 1f }

  condition:
    any of them
}