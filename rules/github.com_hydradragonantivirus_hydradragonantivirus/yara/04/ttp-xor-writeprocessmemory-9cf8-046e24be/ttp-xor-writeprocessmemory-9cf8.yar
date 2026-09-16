rule TTP_XOR_WriteProcessMemory_9cf8 {
  strings:
    $key_9cf8 = { cb 8a [2] f9 a8 [2] ff 9d [2] d1 9d [2] ee 81 }

  condition:
    any of them
}