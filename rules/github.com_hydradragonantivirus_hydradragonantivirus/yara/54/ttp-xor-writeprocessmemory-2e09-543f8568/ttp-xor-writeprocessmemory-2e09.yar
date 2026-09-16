rule TTP_XOR_WriteProcessMemory_2e09 {
  strings:
    $key_2e09 = { 79 7b [2] 4b 59 [2] 4d 6c [2] 63 6c [2] 5c 70 }

  condition:
    any of them
}