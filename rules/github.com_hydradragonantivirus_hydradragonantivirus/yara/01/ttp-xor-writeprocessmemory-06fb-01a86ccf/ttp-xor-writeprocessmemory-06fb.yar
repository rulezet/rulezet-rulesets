rule TTP_XOR_WriteProcessMemory_06fb {
  strings:
    $key_06fb = { 51 89 [2] 63 ab [2] 65 9e [2] 4b 9e [2] 74 82 }

  condition:
    any of them
}