rule TTP_XOR_WriteProcessMemory_19e9 {
  strings:
    $key_19e9 = { 4e 9b [2] 7c b9 [2] 7a 8c [2] 54 8c [2] 6b 90 }

  condition:
    any of them
}