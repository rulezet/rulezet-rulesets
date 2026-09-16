rule TTP_XOR_WriteProcessMemory_9c37 {
  strings:
    $key_9c37 = { cb 45 [2] f9 67 [2] ff 52 [2] d1 52 [2] ee 4e }

  condition:
    any of them
}