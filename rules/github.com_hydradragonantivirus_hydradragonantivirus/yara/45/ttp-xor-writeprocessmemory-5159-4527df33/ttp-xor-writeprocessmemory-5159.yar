rule TTP_XOR_WriteProcessMemory_5159 {
  strings:
    $key_5159 = { 06 2b [2] 34 09 [2] 32 3c [2] 1c 3c [2] 23 20 }

  condition:
    any of them
}