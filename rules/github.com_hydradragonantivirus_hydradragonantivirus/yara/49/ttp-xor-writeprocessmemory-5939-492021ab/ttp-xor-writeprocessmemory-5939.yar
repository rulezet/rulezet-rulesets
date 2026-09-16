rule TTP_XOR_WriteProcessMemory_5939 {
  strings:
    $key_5939 = { 0e 4b [2] 3c 69 [2] 3a 5c [2] 14 5c [2] 2b 40 }

  condition:
    any of them
}