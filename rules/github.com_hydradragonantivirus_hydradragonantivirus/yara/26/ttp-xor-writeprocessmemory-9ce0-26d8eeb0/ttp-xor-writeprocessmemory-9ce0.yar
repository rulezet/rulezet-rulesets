rule TTP_XOR_WriteProcessMemory_9ce0 {
  strings:
    $key_9ce0 = { cb 92 [2] f9 b0 [2] ff 85 [2] d1 85 [2] ee 99 }

  condition:
    any of them
}