rule TTP_XOR_WriteProcessMemory_9c50 {
  strings:
    $key_9c50 = { cb 22 [2] f9 00 [2] ff 35 [2] d1 35 [2] ee 29 }

  condition:
    any of them
}