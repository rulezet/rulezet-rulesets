rule TTP_XOR_WriteProcessMemory_2fd0 {
  strings:
    $key_2fd0 = { 78 a2 [2] 4a 80 [2] 4c b5 [2] 62 b5 [2] 5d a9 }

  condition:
    any of them
}