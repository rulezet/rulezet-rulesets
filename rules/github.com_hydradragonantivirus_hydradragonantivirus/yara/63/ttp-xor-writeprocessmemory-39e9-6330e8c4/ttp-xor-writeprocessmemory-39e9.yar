rule TTP_XOR_WriteProcessMemory_39e9 {
  strings:
    $key_39e9 = { 6e 9b [2] 5c b9 [2] 5a 8c [2] 74 8c [2] 4b 90 }

  condition:
    any of them
}