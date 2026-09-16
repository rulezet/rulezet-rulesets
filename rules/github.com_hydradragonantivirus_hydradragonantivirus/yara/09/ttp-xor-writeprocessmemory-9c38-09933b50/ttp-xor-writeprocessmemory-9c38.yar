rule TTP_XOR_WriteProcessMemory_9c38 {
  strings:
    $key_9c38 = { cb 4a [2] f9 68 [2] ff 5d [2] d1 5d [2] ee 41 }

  condition:
    any of them
}