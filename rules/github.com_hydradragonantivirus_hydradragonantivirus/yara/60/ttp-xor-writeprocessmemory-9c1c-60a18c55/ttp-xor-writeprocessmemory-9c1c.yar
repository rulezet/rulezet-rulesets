rule TTP_XOR_WriteProcessMemory_9c1c {
  strings:
    $key_9c1c = { cb 6e [2] f9 4c [2] ff 79 [2] d1 79 [2] ee 65 }

  condition:
    any of them
}