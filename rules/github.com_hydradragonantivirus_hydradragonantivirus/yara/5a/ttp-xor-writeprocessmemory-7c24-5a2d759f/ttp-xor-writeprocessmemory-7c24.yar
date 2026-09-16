rule TTP_XOR_WriteProcessMemory_7c24 {
  strings:
    $key_7c24 = { 2b 56 [2] 19 74 [2] 1f 41 [2] 31 41 [2] 0e 5d }

  condition:
    any of them
}