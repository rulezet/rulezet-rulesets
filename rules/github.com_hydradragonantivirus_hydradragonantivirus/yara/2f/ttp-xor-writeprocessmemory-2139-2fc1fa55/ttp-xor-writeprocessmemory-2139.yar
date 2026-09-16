rule TTP_XOR_WriteProcessMemory_2139 {
  strings:
    $key_2139 = { 76 4b [2] 44 69 [2] 42 5c [2] 6c 5c [2] 53 40 }

  condition:
    any of them
}