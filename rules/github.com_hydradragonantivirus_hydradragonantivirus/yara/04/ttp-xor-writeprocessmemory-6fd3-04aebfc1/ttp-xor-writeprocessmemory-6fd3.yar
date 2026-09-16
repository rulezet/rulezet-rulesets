rule TTP_XOR_WriteProcessMemory_6fd3 {
  strings:
    $key_6fd3 = { 38 a1 [2] 0a 83 [2] 0c b6 [2] 22 b6 [2] 1d aa }

  condition:
    any of them
}