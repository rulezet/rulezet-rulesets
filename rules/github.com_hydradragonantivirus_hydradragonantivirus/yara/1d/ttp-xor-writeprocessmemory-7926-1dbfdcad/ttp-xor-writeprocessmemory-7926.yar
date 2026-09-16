rule TTP_XOR_WriteProcessMemory_7926 {
  strings:
    $key_7926 = { 2e 54 [2] 1c 76 [2] 1a 43 [2] 34 43 [2] 0b 5f }

  condition:
    any of them
}