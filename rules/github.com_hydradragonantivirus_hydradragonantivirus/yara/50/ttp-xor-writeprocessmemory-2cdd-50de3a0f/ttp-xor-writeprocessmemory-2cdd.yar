rule TTP_XOR_WriteProcessMemory_2cdd {
  strings:
    $key_2cdd = { 7b af [2] 49 8d [2] 4f b8 [2] 61 b8 [2] 5e a4 }

  condition:
    any of them
}