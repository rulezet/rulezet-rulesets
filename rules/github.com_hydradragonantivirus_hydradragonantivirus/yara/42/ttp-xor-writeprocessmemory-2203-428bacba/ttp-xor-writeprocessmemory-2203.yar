rule TTP_XOR_WriteProcessMemory_2203 {
  strings:
    $key_2203 = { 75 71 [2] 47 53 [2] 41 66 [2] 6f 66 [2] 50 7a }

  condition:
    any of them
}