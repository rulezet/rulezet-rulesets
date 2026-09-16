rule TTP_XOR_WriteProcessMemory_8219 {
  strings:
    $key_8219 = { d5 6b [2] e7 49 [2] e1 7c [2] cf 7c [2] f0 60 }

  condition:
    any of them
}