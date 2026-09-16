rule TTP_XOR_WriteProcessMemory_9ce8 {
  strings:
    $key_9ce8 = { cb 9a [2] f9 b8 [2] ff 8d [2] d1 8d [2] ee 91 }

  condition:
    any of them
}