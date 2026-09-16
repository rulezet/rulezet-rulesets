rule TTP_XOR_WriteProcessMemory_4b74 {
  strings:
    $key_4b74 = { 1c 06 [2] 2e 24 [2] 28 11 [2] 06 11 [2] 39 0d }

  condition:
    any of them
}