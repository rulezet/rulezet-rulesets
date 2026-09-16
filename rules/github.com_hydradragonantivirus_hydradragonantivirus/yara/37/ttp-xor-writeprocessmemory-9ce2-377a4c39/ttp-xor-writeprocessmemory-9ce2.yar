rule TTP_XOR_WriteProcessMemory_9ce2 {
  strings:
    $key_9ce2 = { cb 90 [2] f9 b2 [2] ff 87 [2] d1 87 [2] ee 9b }

  condition:
    any of them
}