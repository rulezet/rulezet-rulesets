rule TTP_XOR_WriteProcessMemory_5b74 {
  strings:
    $key_5b74 = { 0c 06 [2] 3e 24 [2] 38 11 [2] 16 11 [2] 29 0d }

  condition:
    any of them
}