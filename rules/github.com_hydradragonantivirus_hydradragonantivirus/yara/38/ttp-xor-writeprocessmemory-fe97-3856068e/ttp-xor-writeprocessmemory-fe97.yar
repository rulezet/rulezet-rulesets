rule TTP_XOR_WriteProcessMemory_fe97 {
  strings:
    $key_fe97 = { a9 e5 [2] 9b c7 [2] 9d f2 [2] b3 f2 [2] 8c ee }

  condition:
    any of them
}