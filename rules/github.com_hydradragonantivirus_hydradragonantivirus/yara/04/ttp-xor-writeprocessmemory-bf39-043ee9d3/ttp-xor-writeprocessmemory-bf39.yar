rule TTP_XOR_WriteProcessMemory_bf39 {
  strings:
    $key_bf39 = { e8 4b [2] da 69 [2] dc 5c [2] f2 5c [2] cd 40 }

  condition:
    any of them
}