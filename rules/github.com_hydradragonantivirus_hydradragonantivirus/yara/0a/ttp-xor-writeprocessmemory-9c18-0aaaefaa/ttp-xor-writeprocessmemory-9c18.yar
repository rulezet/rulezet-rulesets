rule TTP_XOR_WriteProcessMemory_9c18 {
  strings:
    $key_9c18 = { cb 6a [2] f9 48 [2] ff 7d [2] d1 7d [2] ee 61 }

  condition:
    any of them
}