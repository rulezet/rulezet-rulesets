rule TTP_XOR_WriteProcessMemory_0a04 {
  strings:
    $key_0a04 = { 5d 76 [2] 6f 54 [2] 69 61 [2] 47 61 [2] 78 7d }

  condition:
    any of them
}