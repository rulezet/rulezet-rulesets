rule TTP_XOR_WriteProcessMemory_6941 {
  strings:
    $key_6941 = { 3e 33 [2] 0c 11 [2] 0a 24 [2] 24 24 [2] 1b 38 }

  condition:
    any of them
}