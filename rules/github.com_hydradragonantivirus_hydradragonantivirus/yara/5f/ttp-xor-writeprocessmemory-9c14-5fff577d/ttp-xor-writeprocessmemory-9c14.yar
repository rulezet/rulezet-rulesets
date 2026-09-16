rule TTP_XOR_WriteProcessMemory_9c14 {
  strings:
    $key_9c14 = { cb 66 [2] f9 44 [2] ff 71 [2] d1 71 [2] ee 6d }

  condition:
    any of them
}