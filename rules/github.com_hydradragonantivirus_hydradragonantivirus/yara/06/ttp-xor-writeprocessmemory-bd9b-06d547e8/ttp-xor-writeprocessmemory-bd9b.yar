rule TTP_XOR_WriteProcessMemory_bd9b {
  strings:
    $key_bd9b = { ea e9 [2] d8 cb [2] de fe [2] f0 fe [2] cf e2 }

  condition:
    any of them
}