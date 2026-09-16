rule TTP_XOR_WriteProcessMemory_7bfe {
  strings:
    $key_7bfe = { 2c 8c [2] 1e ae [2] 18 9b [2] 36 9b [2] 09 87 }

  condition:
    any of them
}