rule TTP_XOR_WriteProcessMemory_07ff {
  strings:
    $key_07ff = { 50 8d [2] 62 af [2] 64 9a [2] 4a 9a [2] 75 86 }

  condition:
    any of them
}