rule TTP_XOR_WriteProcessMemory_9c19 {
  strings:
    $key_9c19 = { cb 6b [2] f9 49 [2] ff 7c [2] d1 7c [2] ee 60 }

  condition:
    any of them
}