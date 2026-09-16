rule TTP_XOR_WriteProcessMemory_9cf5 {
  strings:
    $key_9cf5 = { cb 87 [2] f9 a5 [2] ff 90 [2] d1 90 [2] ee 8c }

  condition:
    any of them
}