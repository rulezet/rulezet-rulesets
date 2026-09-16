rule TTP_XOR_WriteProcessMemory_9c5f {
  strings:
    $key_9c5f = { cb 2d [2] f9 0f [2] ff 3a [2] d1 3a [2] ee 26 }

  condition:
    any of them
}