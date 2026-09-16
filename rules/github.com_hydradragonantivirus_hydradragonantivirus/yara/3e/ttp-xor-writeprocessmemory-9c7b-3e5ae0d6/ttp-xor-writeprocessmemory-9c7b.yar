rule TTP_XOR_WriteProcessMemory_9c7b {
  strings:
    $key_9c7b = { cb 09 [2] f9 2b [2] ff 1e [2] d1 1e [2] ee 02 }

  condition:
    any of them
}