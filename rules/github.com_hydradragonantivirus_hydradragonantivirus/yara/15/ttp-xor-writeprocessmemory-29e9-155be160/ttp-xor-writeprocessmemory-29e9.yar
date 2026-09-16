rule TTP_XOR_WriteProcessMemory_29e9 {
  strings:
    $key_29e9 = { 7e 9b [2] 4c b9 [2] 4a 8c [2] 64 8c [2] 5b 90 }

  condition:
    any of them
}