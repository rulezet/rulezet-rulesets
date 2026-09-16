rule TTP_XOR_WriteProcessMemory_9c48 {
  strings:
    $key_9c48 = { cb 3a [2] f9 18 [2] ff 2d [2] d1 2d [2] ee 31 }

  condition:
    any of them
}