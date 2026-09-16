rule TTP_XOR_WriteProcessMemory_9ce5 {
  strings:
    $key_9ce5 = { cb 97 [2] f9 b5 [2] ff 80 [2] d1 80 [2] ee 9c }

  condition:
    any of them
}