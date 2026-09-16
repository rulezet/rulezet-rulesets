rule TTP_XOR_WriteProcessMemory_9c69 {
  strings:
    $key_9c69 = { cb 1b [2] f9 39 [2] ff 0c [2] d1 0c [2] ee 10 }

  condition:
    any of them
}