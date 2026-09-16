rule TTP_XOR_WriteProcessMemory_9c3e {
  strings:
    $key_9c3e = { cb 4c [2] f9 6e [2] ff 5b [2] d1 5b [2] ee 47 }

  condition:
    any of them
}