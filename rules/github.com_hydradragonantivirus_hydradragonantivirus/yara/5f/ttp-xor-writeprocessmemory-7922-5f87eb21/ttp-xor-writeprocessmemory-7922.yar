rule TTP_XOR_WriteProcessMemory_7922 {
  strings:
    $key_7922 = { 2e 50 [2] 1c 72 [2] 1a 47 [2] 34 47 [2] 0b 5b }

  condition:
    any of them
}