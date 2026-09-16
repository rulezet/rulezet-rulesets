rule TTP_XOR_WriteProcessMemory_9c34 {
  strings:
    $key_9c34 = { cb 46 [2] f9 64 [2] ff 51 [2] d1 51 [2] ee 4d }

  condition:
    any of them
}