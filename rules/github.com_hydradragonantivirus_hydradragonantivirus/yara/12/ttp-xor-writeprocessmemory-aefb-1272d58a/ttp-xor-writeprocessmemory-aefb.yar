rule TTP_XOR_WriteProcessMemory_aefb {
  strings:
    $key_aefb = { f9 89 [2] cb ab [2] cd 9e [2] e3 9e [2] dc 82 }

  condition:
    any of them
}