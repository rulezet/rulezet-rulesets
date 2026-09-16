rule TTP_XOR_WriteProcessMemory_9cf4 {
  strings:
    $key_9cf4 = { cb 86 [2] f9 a4 [2] ff 91 [2] d1 91 [2] ee 8d }

  condition:
    any of them
}