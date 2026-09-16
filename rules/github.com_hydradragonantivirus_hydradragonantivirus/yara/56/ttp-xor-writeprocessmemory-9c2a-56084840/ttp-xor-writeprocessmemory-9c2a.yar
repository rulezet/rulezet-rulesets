rule TTP_XOR_WriteProcessMemory_9c2a {
  strings:
    $key_9c2a = { cb 58 [2] f9 7a [2] ff 4f [2] d1 4f [2] ee 53 }

  condition:
    any of them
}