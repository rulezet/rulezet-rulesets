rule TTP_XOR_WriteProcessMemory_bf75 {
  strings:
    $key_bf75 = { e8 07 [2] da 25 [2] dc 10 [2] f2 10 [2] cd 0c }

  condition:
    any of them
}