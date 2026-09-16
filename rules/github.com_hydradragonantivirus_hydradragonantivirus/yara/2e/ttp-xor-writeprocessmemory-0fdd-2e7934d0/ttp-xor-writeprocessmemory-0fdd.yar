rule TTP_XOR_WriteProcessMemory_0fdd {
  strings:
    $key_0fdd = { 58 af [2] 6a 8d [2] 6c b8 [2] 42 b8 [2] 7d a4 }

  condition:
    any of them
}