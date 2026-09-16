rule TTP_XOR_WriteProcessMemory_7439 {
  strings:
    $key_7439 = { 23 4b [2] 11 69 [2] 17 5c [2] 39 5c [2] 06 40 }

  condition:
    any of them
}