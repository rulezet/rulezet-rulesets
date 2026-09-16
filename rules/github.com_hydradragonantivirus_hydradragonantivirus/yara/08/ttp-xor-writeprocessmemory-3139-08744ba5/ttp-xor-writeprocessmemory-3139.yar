rule TTP_XOR_WriteProcessMemory_3139 {
  strings:
    $key_3139 = { 66 4b [2] 54 69 [2] 52 5c [2] 7c 5c [2] 43 40 }

  condition:
    any of them
}