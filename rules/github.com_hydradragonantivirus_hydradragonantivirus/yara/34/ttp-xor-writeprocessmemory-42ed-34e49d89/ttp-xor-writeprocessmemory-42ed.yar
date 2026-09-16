rule TTP_XOR_WriteProcessMemory_42ed {
  strings:
    $key_42ed = { 15 9f [2] 27 bd [2] 21 88 [2] 0f 88 [2] 30 94 }

  condition:
    any of them
}