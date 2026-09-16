rule TTP_XOR_WriteProcessMemory_9c2c {
  strings:
    $key_9c2c = { cb 5e [2] f9 7c [2] ff 49 [2] d1 49 [2] ee 55 }

  condition:
    any of them
}