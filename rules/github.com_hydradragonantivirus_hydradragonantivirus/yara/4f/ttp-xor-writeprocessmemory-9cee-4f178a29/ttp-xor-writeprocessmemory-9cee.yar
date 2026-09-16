rule TTP_XOR_WriteProcessMemory_9cee {
  strings:
    $key_9cee = { cb 9c [2] f9 be [2] ff 8b [2] d1 8b [2] ee 97 }

  condition:
    any of them
}