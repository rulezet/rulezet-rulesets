rule TTP_XOR_WriteProcessMemory_4231 {
  strings:
    $key_4231 = { 15 43 [2] 27 61 [2] 21 54 [2] 0f 54 [2] 30 48 }

  condition:
    any of them
}