rule TTP_XOR_WriteProcessMemory_5222 {
  strings:
    $key_5222 = { 05 50 [2] 37 72 [2] 31 47 [2] 1f 47 [2] 20 5b }

  condition:
    any of them
}