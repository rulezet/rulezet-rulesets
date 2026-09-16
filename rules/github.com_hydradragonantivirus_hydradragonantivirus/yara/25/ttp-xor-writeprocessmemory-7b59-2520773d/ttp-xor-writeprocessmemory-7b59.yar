rule TTP_XOR_WriteProcessMemory_7b59 {
  strings:
    $key_7b59 = { 2c 2b [2] 1e 09 [2] 18 3c [2] 36 3c [2] 09 20 }

  condition:
    any of them
}