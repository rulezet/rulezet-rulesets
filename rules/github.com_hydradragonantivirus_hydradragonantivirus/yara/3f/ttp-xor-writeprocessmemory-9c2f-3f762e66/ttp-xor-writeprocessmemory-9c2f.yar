rule TTP_XOR_WriteProcessMemory_9c2f {
  strings:
    $key_9c2f = { cb 5d [2] f9 7f [2] ff 4a [2] d1 4a [2] ee 56 }

  condition:
    any of them
}