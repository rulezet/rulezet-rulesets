rule TTP_XOR_WriteProcessMemory_223d {
  strings:
    $key_223d = { 75 4f [2] 47 6d [2] 41 58 [2] 6f 58 [2] 50 44 }

  condition:
    any of them
}