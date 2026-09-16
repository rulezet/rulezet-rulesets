rule TTP_XOR_WriteProcessMemory_3639 {
  strings:
    $key_3639 = { 61 4b [2] 53 69 [2] 55 5c [2] 7b 5c [2] 44 40 }

  condition:
    any of them
}