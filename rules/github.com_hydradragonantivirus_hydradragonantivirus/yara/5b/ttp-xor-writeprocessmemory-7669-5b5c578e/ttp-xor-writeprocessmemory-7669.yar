rule TTP_XOR_WriteProcessMemory_7669 {
  strings:
    $key_7669 = { 21 1b [2] 13 39 [2] 15 0c [2] 3b 0c [2] 04 10 }

  condition:
    any of them
}