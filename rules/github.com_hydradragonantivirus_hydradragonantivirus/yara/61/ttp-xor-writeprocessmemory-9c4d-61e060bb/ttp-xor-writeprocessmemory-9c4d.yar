rule TTP_XOR_WriteProcessMemory_9c4d {
  strings:
    $key_9c4d = { cb 3f [2] f9 1d [2] ff 28 [2] d1 28 [2] ee 34 }

  condition:
    any of them
}