rule TTP_XOR_WriteProcessMemory_69e9 {
  strings:
    $key_69e9 = { 3e 9b [2] 0c b9 [2] 0a 8c [2] 24 8c [2] 1b 90 }

  condition:
    any of them
}