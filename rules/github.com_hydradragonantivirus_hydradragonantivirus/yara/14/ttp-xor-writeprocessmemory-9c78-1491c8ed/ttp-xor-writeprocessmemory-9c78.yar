rule TTP_XOR_WriteProcessMemory_9c78 {
  strings:
    $key_9c78 = { cb 0a [2] f9 28 [2] ff 1d [2] d1 1d [2] ee 01 }

  condition:
    any of them
}