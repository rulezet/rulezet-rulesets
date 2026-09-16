rule TTP_XOR_WriteProcessMemory_9c23 {
  strings:
    $key_9c23 = { cb 51 [2] f9 73 [2] ff 46 [2] d1 46 [2] ee 5a }

  condition:
    any of them
}