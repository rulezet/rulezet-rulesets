rule TTP_XOR_WriteProcessMemory_7f39 {
  strings:
    $key_7f39 = { 28 4b [2] 1a 69 [2] 1c 5c [2] 32 5c [2] 0d 40 }

  condition:
    any of them
}