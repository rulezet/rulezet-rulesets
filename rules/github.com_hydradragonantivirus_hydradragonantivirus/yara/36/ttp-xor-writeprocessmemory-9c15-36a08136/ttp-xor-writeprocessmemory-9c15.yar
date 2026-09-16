rule TTP_XOR_WriteProcessMemory_9c15 {
  strings:
    $key_9c15 = { cb 67 [2] f9 45 [2] ff 70 [2] d1 70 [2] ee 6c }

  condition:
    any of them
}