rule TTP_XOR_WriteProcessMemory_9c13 {
  strings:
    $key_9c13 = { cb 61 [2] f9 43 [2] ff 76 [2] d1 76 [2] ee 6a }

  condition:
    any of them
}