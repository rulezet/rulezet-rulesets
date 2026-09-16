rule TTP_XOR_WriteProcessMemory_2404 {
  strings:
    $key_2404 = { 73 76 [2] 41 54 [2] 47 61 [2] 69 61 [2] 56 7d }

  condition:
    any of them
}