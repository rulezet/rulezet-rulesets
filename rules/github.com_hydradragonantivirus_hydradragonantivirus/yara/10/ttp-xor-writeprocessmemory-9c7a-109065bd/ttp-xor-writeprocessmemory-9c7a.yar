rule TTP_XOR_WriteProcessMemory_9c7a {
  strings:
    $key_9c7a = { cb 08 [2] f9 2a [2] ff 1f [2] d1 1f [2] ee 03 }

  condition:
    any of them
}