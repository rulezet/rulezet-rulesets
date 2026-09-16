rule TTP_XOR_WriteProcessMemory_30ca {
  strings:
    $key_30ca = { 67 b8 [2] 55 9a [2] 53 af [2] 7d af [2] 42 b3 }

  condition:
    any of them
}