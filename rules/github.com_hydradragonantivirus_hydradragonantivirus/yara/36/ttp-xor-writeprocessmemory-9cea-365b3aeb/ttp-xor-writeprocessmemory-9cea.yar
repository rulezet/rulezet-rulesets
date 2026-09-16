rule TTP_XOR_WriteProcessMemory_9cea {
  strings:
    $key_9cea = { cb 98 [2] f9 ba [2] ff 8f [2] d1 8f [2] ee 93 }

  condition:
    any of them
}