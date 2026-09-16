rule TTP_XOR_WriteProcessMemory_aefe {
  strings:
    $key_aefe = { f9 8c [2] cb ae [2] cd 9b [2] e3 9b [2] dc 87 }

  condition:
    any of them
}