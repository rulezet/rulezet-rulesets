rule TTP_XOR_WriteProcessMemory_9c65 {
  strings:
    $key_9c65 = { cb 17 [2] f9 35 [2] ff 00 [2] d1 00 [2] ee 1c }

  condition:
    any of them
}