rule TTP_XOR_WriteProcessMemory_18ed {
  strings:
    $key_18ed = { 4f 9f [2] 7d bd [2] 7b 88 [2] 55 88 [2] 6a 94 }

  condition:
    any of them
}