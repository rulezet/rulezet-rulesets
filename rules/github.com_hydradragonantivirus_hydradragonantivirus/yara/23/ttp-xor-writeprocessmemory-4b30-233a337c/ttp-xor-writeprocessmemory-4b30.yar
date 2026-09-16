rule TTP_XOR_WriteProcessMemory_4b30 {
  strings:
    $key_4b30 = { 1c 42 [2] 2e 60 [2] 28 55 [2] 06 55 [2] 39 49 }

  condition:
    any of them
}