rule TTP_XOR_WriteProcessMemory_9c47 {
  strings:
    $key_9c47 = { cb 35 [2] f9 17 [2] ff 22 [2] d1 22 [2] ee 3e }

  condition:
    any of them
}