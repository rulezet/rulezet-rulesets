rule TTP_XOR_WriteProcessMemory_260d {
  strings:
    $key_260d = { 71 7f [2] 43 5d [2] 45 68 [2] 6b 68 [2] 54 74 }

  condition:
    any of them
}