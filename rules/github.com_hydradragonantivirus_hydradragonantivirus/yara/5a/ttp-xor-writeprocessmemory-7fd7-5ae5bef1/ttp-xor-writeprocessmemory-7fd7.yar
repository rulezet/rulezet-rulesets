rule TTP_XOR_WriteProcessMemory_7fd7 {
  strings:
    $key_7fd7 = { 28 a5 [2] 1a 87 [2] 1c b2 [2] 32 b2 [2] 0d ae }

  condition:
    any of them
}