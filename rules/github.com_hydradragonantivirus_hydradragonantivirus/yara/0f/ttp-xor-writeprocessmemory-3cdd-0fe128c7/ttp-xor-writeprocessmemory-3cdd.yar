rule TTP_XOR_WriteProcessMemory_3cdd {
  strings:
    $key_3cdd = { 6b af [2] 59 8d [2] 5f b8 [2] 71 b8 [2] 4e a4 }

  condition:
    any of them
}