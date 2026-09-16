rule TTP_XOR_WriteProcessMemory_5fd3 {
  strings:
    $key_5fd3 = { 08 a1 [2] 3a 83 [2] 3c b6 [2] 12 b6 [2] 2d aa }

  condition:
    any of them
}