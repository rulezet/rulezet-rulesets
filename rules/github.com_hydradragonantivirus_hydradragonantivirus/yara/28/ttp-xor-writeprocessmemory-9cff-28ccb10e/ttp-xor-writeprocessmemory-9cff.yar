rule TTP_XOR_WriteProcessMemory_9cff {
  strings:
    $key_9cff = { cb 8d [2] f9 af [2] ff 9a [2] d1 9a [2] ee 86 }

  condition:
    any of them
}