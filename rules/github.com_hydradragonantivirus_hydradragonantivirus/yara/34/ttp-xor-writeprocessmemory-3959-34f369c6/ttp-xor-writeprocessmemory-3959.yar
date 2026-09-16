rule TTP_XOR_WriteProcessMemory_3959 {
  strings:
    $key_3959 = { 6e 2b [2] 5c 09 [2] 5a 3c [2] 74 3c [2] 4b 20 }

  condition:
    any of them
}