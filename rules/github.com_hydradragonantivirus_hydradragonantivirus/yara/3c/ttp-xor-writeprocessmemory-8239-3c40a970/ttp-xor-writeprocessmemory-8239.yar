rule TTP_XOR_WriteProcessMemory_8239 {
  strings:
    $key_8239 = { d5 4b [2] e7 69 [2] e1 5c [2] cf 5c [2] f0 40 }

  condition:
    any of them
}