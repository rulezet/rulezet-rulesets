rule TTP_XOR_WriteProcessMemory_9ce4 {
  strings:
    $key_9ce4 = { cb 96 [2] f9 b4 [2] ff 81 [2] d1 81 [2] ee 9d }

  condition:
    any of them
}