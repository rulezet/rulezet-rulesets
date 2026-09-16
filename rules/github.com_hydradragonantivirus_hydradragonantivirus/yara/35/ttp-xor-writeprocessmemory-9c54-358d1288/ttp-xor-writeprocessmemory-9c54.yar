rule TTP_XOR_WriteProcessMemory_9c54 {
  strings:
    $key_9c54 = { cb 26 [2] f9 04 [2] ff 31 [2] d1 31 [2] ee 2d }

  condition:
    any of them
}