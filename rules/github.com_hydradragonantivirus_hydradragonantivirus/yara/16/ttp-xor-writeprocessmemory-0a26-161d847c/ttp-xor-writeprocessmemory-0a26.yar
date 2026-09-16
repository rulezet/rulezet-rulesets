rule TTP_XOR_WriteProcessMemory_0a26 {
  strings:
    $key_0a26 = { 5d 54 [2] 6f 76 [2] 69 43 [2] 47 43 [2] 78 5f }

  condition:
    any of them
}