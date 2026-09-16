rule TTP_XOR_WriteProcessMemory_7ec0 {
  strings:
    $key_7ec0 = { 29 b2 [2] 1b 90 [2] 1d a5 [2] 33 a5 [2] 0c b9 }

  condition:
    any of them
}