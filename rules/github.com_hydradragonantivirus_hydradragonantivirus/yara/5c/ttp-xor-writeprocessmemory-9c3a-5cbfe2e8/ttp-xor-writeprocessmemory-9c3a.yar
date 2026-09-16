rule TTP_XOR_WriteProcessMemory_9c3a {
  strings:
    $key_9c3a = { cb 48 [2] f9 6a [2] ff 5f [2] d1 5f [2] ee 43 }

  condition:
    any of them
}