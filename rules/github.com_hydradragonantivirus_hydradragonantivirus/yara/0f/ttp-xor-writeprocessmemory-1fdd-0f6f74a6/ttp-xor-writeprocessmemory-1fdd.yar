rule TTP_XOR_WriteProcessMemory_1fdd {
  strings:
    $key_1fdd = { 48 af [2] 7a 8d [2] 7c b8 [2] 52 b8 [2] 6d a4 }

  condition:
    any of them
}