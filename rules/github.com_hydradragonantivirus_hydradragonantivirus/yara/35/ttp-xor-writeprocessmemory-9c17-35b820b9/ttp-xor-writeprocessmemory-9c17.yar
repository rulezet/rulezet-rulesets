rule TTP_XOR_WriteProcessMemory_9c17 {
  strings:
    $key_9c17 = { cb 65 [2] f9 47 [2] ff 72 [2] d1 72 [2] ee 6e }

  condition:
    any of them
}