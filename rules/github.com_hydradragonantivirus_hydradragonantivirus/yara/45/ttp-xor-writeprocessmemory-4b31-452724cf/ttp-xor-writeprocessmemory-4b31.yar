rule TTP_XOR_WriteProcessMemory_4b31 {
  strings:
    $key_4b31 = { 1c 43 [2] 2e 61 [2] 28 54 [2] 06 54 [2] 39 48 }

  condition:
    any of them
}