rule TTP_XOR_WriteProcessMemory_9c1f {
  strings:
    $key_9c1f = { cb 6d [2] f9 4f [2] ff 7a [2] d1 7a [2] ee 66 }

  condition:
    any of them
}