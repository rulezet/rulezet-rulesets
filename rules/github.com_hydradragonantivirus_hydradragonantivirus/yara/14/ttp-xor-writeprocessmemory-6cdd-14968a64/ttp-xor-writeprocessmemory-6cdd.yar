rule TTP_XOR_WriteProcessMemory_6cdd {
  strings:
    $key_6cdd = { 3b af [2] 09 8d [2] 0f b8 [2] 21 b8 [2] 1e a4 }

  condition:
    any of them
}