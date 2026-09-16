rule TTP_XOR_WriteProcessMemory_9c3d {
  strings:
    $key_9c3d = { cb 4f [2] f9 6d [2] ff 58 [2] d1 58 [2] ee 44 }

  condition:
    any of them
}