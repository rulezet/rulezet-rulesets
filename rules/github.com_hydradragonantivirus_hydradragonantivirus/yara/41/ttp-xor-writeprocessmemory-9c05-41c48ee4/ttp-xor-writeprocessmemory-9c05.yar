rule TTP_XOR_WriteProcessMemory_9c05 {
  strings:
    $key_9c05 = { cb 77 [2] f9 55 [2] ff 60 [2] d1 60 [2] ee 7c }

  condition:
    any of them
}