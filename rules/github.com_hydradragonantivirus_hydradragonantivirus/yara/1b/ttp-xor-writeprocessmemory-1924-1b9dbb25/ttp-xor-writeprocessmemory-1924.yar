rule TTP_XOR_WriteProcessMemory_1924 {
  strings:
    $key_1924 = { 4e 56 [2] 7c 74 [2] 7a 41 [2] 54 41 [2] 6b 5d }

  condition:
    any of them
}