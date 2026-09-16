rule TTP_XOR_WriteProcessMemory_82ee {
  strings:
    $key_82ee = { d5 9c [2] e7 be [2] e1 8b [2] cf 8b [2] f0 97 }

  condition:
    any of them
}