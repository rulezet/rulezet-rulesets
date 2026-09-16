rule TTP_XOR_WriteProcessMemory_0fd0 {
  strings:
    $key_0fd0 = { 58 a2 [2] 6a 80 [2] 6c b5 [2] 42 b5 [2] 7d a9 }

  condition:
    any of them
}