rule TTP_XOR_WriteProcessMemory_3fdd {
  strings:
    $key_3fdd = { 68 af [2] 5a 8d [2] 5c b8 [2] 72 b8 [2] 4d a4 }

  condition:
    any of them
}