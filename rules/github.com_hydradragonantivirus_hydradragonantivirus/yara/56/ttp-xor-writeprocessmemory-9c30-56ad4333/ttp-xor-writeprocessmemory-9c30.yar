rule TTP_XOR_WriteProcessMemory_9c30 {
  strings:
    $key_9c30 = { cb 42 [2] f9 60 [2] ff 55 [2] d1 55 [2] ee 49 }

  condition:
    any of them
}