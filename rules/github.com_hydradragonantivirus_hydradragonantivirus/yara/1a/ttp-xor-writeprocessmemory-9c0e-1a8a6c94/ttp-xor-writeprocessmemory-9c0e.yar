rule TTP_XOR_WriteProcessMemory_9c0e {
  strings:
    $key_9c0e = { cb 7c [2] f9 5e [2] ff 6b [2] d1 6b [2] ee 77 }

  condition:
    any of them
}