rule TTP_XOR_WriteProcessMemory_aeee {
  strings:
    $key_aeee = { f9 9c [2] cb be [2] cd 8b [2] e3 8b [2] dc 97 }

  condition:
    any of them
}