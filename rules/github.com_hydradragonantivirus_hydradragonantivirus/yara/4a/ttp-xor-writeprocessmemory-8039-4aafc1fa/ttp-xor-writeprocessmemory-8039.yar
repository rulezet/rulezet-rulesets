rule TTP_XOR_WriteProcessMemory_8039 {
  strings:
    $key_8039 = { d7 4b [2] e5 69 [2] e3 5c [2] cd 5c [2] f2 40 }

  condition:
    any of them
}