rule TTP_XOR_WriteProcessMemory_7139 {
  strings:
    $key_7139 = { 26 4b [2] 14 69 [2] 12 5c [2] 3c 5c [2] 03 40 }

  condition:
    any of them
}