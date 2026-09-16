rule TTP_XOR_WriteProcessMemory_9187 {
  strings:
    $key_9187 = { c6 f5 [2] f4 d7 [2] f2 e2 [2] dc e2 [2] e3 fe }

  condition:
    any of them
}