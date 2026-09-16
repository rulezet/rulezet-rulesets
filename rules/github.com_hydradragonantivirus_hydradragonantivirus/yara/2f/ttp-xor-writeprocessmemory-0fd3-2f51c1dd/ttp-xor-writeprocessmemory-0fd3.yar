rule TTP_XOR_WriteProcessMemory_0fd3 {
  strings:
    $key_0fd3 = { 58 a1 [2] 6a 83 [2] 6c b6 [2] 42 b6 [2] 7d aa }

  condition:
    any of them
}