rule TTP_XOR_WriteProcessMemory_9139 {
  strings:
    $key_9139 = { c6 4b [2] f4 69 [2] f2 5c [2] dc 5c [2] e3 40 }

  condition:
    any of them
}