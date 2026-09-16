rule TTP_XOR_WriteProcessMemory_9cfe {
  strings:
    $key_9cfe = { cb 8c [2] f9 ae [2] ff 9b [2] d1 9b [2] ee 87 }

  condition:
    any of them
}