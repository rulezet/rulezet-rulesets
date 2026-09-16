rule TTP_XOR_WriteProcessMemory_9cfa {
  strings:
    $key_9cfa = { cb 88 [2] f9 aa [2] ff 9f [2] d1 9f [2] ee 83 }

  condition:
    any of them
}