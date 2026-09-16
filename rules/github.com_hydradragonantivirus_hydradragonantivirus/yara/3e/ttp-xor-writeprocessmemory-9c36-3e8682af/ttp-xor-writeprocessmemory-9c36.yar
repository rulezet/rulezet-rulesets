rule TTP_XOR_WriteProcessMemory_9c36 {
  strings:
    $key_9c36 = { cb 44 [2] f9 66 [2] ff 53 [2] d1 53 [2] ee 4f }

  condition:
    any of them
}