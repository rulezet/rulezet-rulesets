rule TTP_XOR_WriteProcessMemory_9c45 {
  strings:
    $key_9c45 = { cb 37 [2] f9 15 [2] ff 20 [2] d1 20 [2] ee 3c }

  condition:
    any of them
}