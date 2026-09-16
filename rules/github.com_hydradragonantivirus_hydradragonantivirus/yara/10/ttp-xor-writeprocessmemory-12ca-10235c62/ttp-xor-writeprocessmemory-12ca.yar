rule TTP_XOR_WriteProcessMemory_12ca {
  strings:
    $key_12ca = { 45 b8 [2] 77 9a [2] 71 af [2] 5f af [2] 60 b3 }

  condition:
    any of them
}