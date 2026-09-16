rule TTP_XOR_WriteProcessMemory_6933 {
  strings:
    $key_6933 = { 3e 41 [2] 0c 63 [2] 0a 56 [2] 24 56 [2] 1b 4a }

  condition:
    any of them
}