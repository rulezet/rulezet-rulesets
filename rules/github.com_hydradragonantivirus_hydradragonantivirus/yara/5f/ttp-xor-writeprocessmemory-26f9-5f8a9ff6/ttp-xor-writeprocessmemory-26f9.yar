rule TTP_XOR_WriteProcessMemory_26f9 {
  strings:
    $key_26f9 = { 71 8b [2] 43 a9 [2] 45 9c [2] 6b 9c [2] 54 80 }

  condition:
    any of them
}