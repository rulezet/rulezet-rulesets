rule TTP_XOR_WriteProcessMemory_6c24 {
  strings:
    $key_6c24 = { 3b 56 [2] 09 74 [2] 0f 41 [2] 21 41 [2] 1e 5d }

  condition:
    any of them
}