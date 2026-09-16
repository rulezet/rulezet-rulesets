rule TTP_XOR_WriteProcessMemory_9118 {
  strings:
    $key_9118 = { c6 6a [2] f4 48 [2] f2 7d [2] dc 7d [2] e3 61 }

  condition:
    any of them
}