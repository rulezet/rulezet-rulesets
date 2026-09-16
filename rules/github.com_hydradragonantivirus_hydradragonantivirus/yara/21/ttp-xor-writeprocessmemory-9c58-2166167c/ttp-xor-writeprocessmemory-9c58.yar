rule TTP_XOR_WriteProcessMemory_9c58 {
  strings:
    $key_9c58 = { cb 2a [2] f9 08 [2] ff 3d [2] d1 3d [2] ee 21 }

  condition:
    any of them
}