rule TTP_XOR_WriteProcessMemory_4eca {
  strings:
    $key_4eca = { 19 b8 [2] 2b 9a [2] 2d af [2] 03 af [2] 3c b3 }

  condition:
    any of them
}