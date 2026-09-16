rule TTP_XOR_WriteProcessMemory_2fd7 {
  strings:
    $key_2fd7 = { 78 a5 [2] 4a 87 [2] 4c b2 [2] 62 b2 [2] 5d ae }

  condition:
    any of them
}