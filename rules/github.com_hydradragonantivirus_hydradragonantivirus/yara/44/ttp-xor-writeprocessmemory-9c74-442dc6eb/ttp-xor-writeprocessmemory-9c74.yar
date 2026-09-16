rule TTP_XOR_WriteProcessMemory_9c74 {
  strings:
    $key_9c74 = { cb 06 [2] f9 24 [2] ff 11 [2] d1 11 [2] ee 0d }

  condition:
    any of them
}