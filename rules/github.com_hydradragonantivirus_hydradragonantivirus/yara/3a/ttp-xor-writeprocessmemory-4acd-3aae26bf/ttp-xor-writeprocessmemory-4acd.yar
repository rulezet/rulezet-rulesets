rule TTP_XOR_WriteProcessMemory_4acd {
  strings:
    $key_4acd = { 1d bf [2] 2f 9d [2] 29 a8 [2] 07 a8 [2] 38 b4 }

  condition:
    any of them
}