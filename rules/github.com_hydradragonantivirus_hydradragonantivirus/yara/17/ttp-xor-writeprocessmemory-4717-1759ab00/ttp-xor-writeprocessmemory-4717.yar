rule TTP_XOR_WriteProcessMemory_4717 {
  strings:
    $key_4717 = { 10 65 [2] 22 47 [2] 24 72 [2] 0a 72 [2] 35 6e }

  condition:
    any of them
}