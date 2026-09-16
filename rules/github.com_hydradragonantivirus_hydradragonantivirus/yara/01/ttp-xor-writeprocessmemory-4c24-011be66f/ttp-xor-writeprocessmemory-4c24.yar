rule TTP_XOR_WriteProcessMemory_4c24 {
  strings:
    $key_4c24 = { 1b 56 [2] 29 74 [2] 2f 41 [2] 01 41 [2] 3e 5d }

  condition:
    any of them
}