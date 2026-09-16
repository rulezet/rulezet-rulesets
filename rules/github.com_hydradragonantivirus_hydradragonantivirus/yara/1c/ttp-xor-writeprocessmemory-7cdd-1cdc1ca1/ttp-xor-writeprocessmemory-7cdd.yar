rule TTP_XOR_WriteProcessMemory_7cdd {
  strings:
    $key_7cdd = { 2b af [2] 19 8d [2] 1f b8 [2] 31 b8 [2] 0e a4 }

  condition:
    any of them
}