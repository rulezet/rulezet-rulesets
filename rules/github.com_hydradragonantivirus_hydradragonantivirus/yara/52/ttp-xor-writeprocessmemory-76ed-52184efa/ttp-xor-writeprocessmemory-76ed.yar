rule TTP_XOR_WriteProcessMemory_76ed {
  strings:
    $key_76ed = { 21 9f [2] 13 bd [2] 15 88 [2] 3b 88 [2] 04 94 }

  condition:
    any of them
}