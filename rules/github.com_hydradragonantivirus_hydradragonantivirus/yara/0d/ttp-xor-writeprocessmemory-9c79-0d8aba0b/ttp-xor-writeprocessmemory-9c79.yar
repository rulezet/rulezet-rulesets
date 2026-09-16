rule TTP_XOR_WriteProcessMemory_9c79 {
  strings:
    $key_9c79 = { cb 0b [2] f9 29 [2] ff 1c [2] d1 1c [2] ee 00 }

  condition:
    any of them
}