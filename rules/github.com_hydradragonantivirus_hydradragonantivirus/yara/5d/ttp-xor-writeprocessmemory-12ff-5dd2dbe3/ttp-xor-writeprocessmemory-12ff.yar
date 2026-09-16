rule TTP_XOR_WriteProcessMemory_12ff {
  strings:
    $key_12ff = { 45 8d [2] 77 af [2] 71 9a [2] 5f 9a [2] 60 86 }

  condition:
    any of them
}