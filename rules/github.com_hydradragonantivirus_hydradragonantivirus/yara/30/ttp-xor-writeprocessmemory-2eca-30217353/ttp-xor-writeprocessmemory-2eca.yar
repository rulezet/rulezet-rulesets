rule TTP_XOR_WriteProcessMemory_2eca {
  strings:
    $key_2eca = { 79 b8 [2] 4b 9a [2] 4d af [2] 63 af [2] 5c b3 }

  condition:
    any of them
}