rule TTP_XOR_WriteProcessMemory_1c24 {
  strings:
    $key_1c24 = { 4b 56 [2] 79 74 [2] 7f 41 [2] 51 41 [2] 6e 5d }

  condition:
    any of them
}