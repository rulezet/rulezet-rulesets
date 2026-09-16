rule TTP_XOR_WriteProcessMemory_9c03 {
  strings:
    $key_9c03 = { cb 71 [2] f9 53 [2] ff 66 [2] d1 66 [2] ee 7a }

  condition:
    any of them
}