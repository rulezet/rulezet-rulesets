rule TTP_XOR_WriteProcessMemory_9c32 {
  strings:
    $key_9c32 = { cb 40 [2] f9 62 [2] ff 57 [2] d1 57 [2] ee 4b }

  condition:
    any of them
}