rule TTP_XOR_WriteProcessMemory_9c09 {
  strings:
    $key_9c09 = { cb 7b [2] f9 59 [2] ff 6c [2] d1 6c [2] ee 70 }

  condition:
    any of them
}