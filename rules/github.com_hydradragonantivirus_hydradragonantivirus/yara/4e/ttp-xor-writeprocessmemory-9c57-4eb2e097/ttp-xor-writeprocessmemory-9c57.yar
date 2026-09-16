rule TTP_XOR_WriteProcessMemory_9c57 {
  strings:
    $key_9c57 = { cb 25 [2] f9 07 [2] ff 32 [2] d1 32 [2] ee 2e }

  condition:
    any of them
}