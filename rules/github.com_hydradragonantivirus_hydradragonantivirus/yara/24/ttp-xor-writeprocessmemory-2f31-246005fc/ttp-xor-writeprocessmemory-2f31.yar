rule TTP_XOR_WriteProcessMemory_2f31 {
  strings:
    $key_2f31 = { 78 43 [2] 4a 61 [2] 4c 54 [2] 62 54 [2] 5d 48 }

  condition:
    any of them
}