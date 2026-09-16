rule TTP_XOR_WriteProcessMemory_5b31 {
  strings:
    $key_5b31 = { 0c 43 [2] 3e 61 [2] 38 54 [2] 16 54 [2] 29 48 }

  condition:
    any of them
}