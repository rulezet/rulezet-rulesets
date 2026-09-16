rule TTP_XOR_WriteProcessMemory_9c59 {
  strings:
    $key_9c59 = { cb 2b [2] f9 09 [2] ff 3c [2] d1 3c [2] ee 20 }

  condition:
    any of them
}