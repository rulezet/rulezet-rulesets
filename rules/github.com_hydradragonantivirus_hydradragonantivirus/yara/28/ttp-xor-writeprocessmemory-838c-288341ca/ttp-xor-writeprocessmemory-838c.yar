rule TTP_XOR_WriteProcessMemory_838c {
  strings:
    $key_838c = { d4 fe [2] e6 dc [2] e0 e9 [2] ce e9 [2] f1 f5 }

  condition:
    any of them
}