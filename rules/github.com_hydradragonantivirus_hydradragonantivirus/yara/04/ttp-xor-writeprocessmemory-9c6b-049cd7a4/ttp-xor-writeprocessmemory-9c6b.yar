rule TTP_XOR_WriteProcessMemory_9c6b {
  strings:
    $key_9c6b = { cb 19 [2] f9 3b [2] ff 0e [2] d1 0e [2] ee 12 }

  condition:
    any of them
}