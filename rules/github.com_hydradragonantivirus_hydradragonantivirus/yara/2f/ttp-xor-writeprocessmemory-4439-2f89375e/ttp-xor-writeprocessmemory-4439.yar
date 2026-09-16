rule TTP_XOR_WriteProcessMemory_4439 {
  strings:
    $key_4439 = { 13 4b [2] 21 69 [2] 27 5c [2] 09 5c [2] 36 40 }

  condition:
    any of them
}