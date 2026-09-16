rule TTP_XOR_WriteProcessMemory_9ce3 {
  strings:
    $key_9ce3 = { cb 91 [2] f9 b3 [2] ff 86 [2] d1 86 [2] ee 9a }

  condition:
    any of them
}