rule TTP_XOR_WriteProcessMemory_713d {
  strings:
    $key_713d = { 26 4f [2] 14 6d [2] 12 58 [2] 3c 58 [2] 03 44 }

  condition:
    any of them
}