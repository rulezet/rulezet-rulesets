rule TTP_XOR_WriteProcessMemory_3b74 {
  strings:
    $key_3b74 = { 6c 06 [2] 5e 24 [2] 58 11 [2] 76 11 [2] 49 0d }

  condition:
    any of them
}