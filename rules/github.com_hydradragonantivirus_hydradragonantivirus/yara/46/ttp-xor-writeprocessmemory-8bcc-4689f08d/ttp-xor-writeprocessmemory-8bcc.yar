rule TTP_XOR_WriteProcessMemory_8bcc {
  strings:
    $key_8bcc = { dc be [2] ee 9c [2] e8 a9 [2] c6 a9 [2] f9 b5 }

  condition:
    any of them
}