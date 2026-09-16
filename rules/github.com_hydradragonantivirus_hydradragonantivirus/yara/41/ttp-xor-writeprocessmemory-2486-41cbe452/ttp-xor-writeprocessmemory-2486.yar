rule TTP_XOR_WriteProcessMemory_2486 {
  strings:
    $key_2486 = { 73 f4 [2] 41 d6 [2] 47 e3 [2] 69 e3 [2] 56 ff }

  condition:
    any of them
}