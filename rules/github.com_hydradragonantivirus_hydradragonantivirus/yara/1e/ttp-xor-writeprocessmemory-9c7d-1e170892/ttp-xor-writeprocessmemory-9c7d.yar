rule TTP_XOR_WriteProcessMemory_9c7d {
  strings:
    $key_9c7d = { cb 0f [2] f9 2d [2] ff 18 [2] d1 18 [2] ee 04 }

  condition:
    any of them
}