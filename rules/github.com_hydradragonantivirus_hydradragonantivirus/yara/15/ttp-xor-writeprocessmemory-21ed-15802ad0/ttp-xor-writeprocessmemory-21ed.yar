rule TTP_XOR_WriteProcessMemory_21ed {
  strings:
    $key_21ed = { 76 9f [2] 44 bd [2] 42 88 [2] 6c 88 [2] 53 94 }

  condition:
    any of them
}