rule TTP_XOR_WriteProcessMemory_9c3c {
  strings:
    $key_9c3c = { cb 4e [2] f9 6c [2] ff 59 [2] d1 59 [2] ee 45 }

  condition:
    any of them
}