rule TTP_XOR_WriteProcessMemory_36ed {
  strings:
    $key_36ed = { 61 9f [2] 53 bd [2] 55 88 [2] 7b 88 [2] 44 94 }

  condition:
    any of them
}