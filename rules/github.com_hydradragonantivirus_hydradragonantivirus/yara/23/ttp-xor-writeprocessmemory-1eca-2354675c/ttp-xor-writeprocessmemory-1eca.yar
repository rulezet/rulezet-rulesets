rule TTP_XOR_WriteProcessMemory_1eca {
  strings:
    $key_1eca = { 49 b8 [2] 7b 9a [2] 7d af [2] 53 af [2] 6c b3 }

  condition:
    any of them
}