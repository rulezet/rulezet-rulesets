rule TTP_XOR_WriteProcessMemory_aee5 {
  strings:
    $key_aee5 = { f9 97 [2] cb b5 [2] cd 80 [2] e3 80 [2] dc 9c }

  condition:
    any of them
}