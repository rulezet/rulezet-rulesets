rule TTP_XOR_WriteProcessMemory_7469 {
  strings:
    $key_7469 = { 23 1b [2] 11 39 [2] 17 0c [2] 39 0c [2] 06 10 }

  condition:
    any of them
}