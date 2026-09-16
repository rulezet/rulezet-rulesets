rule TTP_XOR_WriteProcessMemory_9c2e {
  strings:
    $key_9c2e = { cb 5c [2] f9 7e [2] ff 4b [2] d1 4b [2] ee 57 }

  condition:
    any of them
}