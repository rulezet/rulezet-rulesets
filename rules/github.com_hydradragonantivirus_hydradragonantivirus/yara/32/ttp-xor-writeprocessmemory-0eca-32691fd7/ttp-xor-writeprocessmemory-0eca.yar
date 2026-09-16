rule TTP_XOR_WriteProcessMemory_0eca {
  strings:
    $key_0eca = { 59 b8 [2] 6b 9a [2] 6d af [2] 43 af [2] 7c b3 }

  condition:
    any of them
}