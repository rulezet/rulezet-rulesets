rule TTP_XOR_WriteProcessMemory_3924 {
  strings:
    $key_3924 = { 6e 56 [2] 5c 74 [2] 5a 41 [2] 74 41 [2] 4b 5d }

  condition:
    any of them
}