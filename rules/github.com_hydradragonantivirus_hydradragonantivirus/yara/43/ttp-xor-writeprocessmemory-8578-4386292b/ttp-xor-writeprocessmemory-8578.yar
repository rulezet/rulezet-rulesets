rule TTP_XOR_WriteProcessMemory_8578 {
  strings:
    $key_8578 = { d2 0a [2] e0 28 [2] e6 1d [2] c8 1d [2] f7 01 }

  condition:
    any of them
}