rule TTP_XOR_WriteProcessMemory_15ca {
  strings:
    $key_15ca = { 42 b8 [2] 70 9a [2] 76 af [2] 58 af [2] 67 b3 }

  condition:
    any of them
}