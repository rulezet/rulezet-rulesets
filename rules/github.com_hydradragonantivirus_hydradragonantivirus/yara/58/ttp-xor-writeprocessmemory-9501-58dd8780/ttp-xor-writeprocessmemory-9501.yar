rule TTP_XOR_WriteProcessMemory_9501 {
  strings:
    $key_9501 = { c2 73 [2] f0 51 [2] f6 64 [2] d8 64 [2] e7 78 }

  condition:
    any of them
}