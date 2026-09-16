rule TTP_XOR_WriteProcessMemory_5fdd {
  strings:
    $key_5fdd = { 08 af [2] 3a 8d [2] 3c b8 [2] 12 b8 [2] 2d a4 }

  condition:
    any of them
}