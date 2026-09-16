rule TTP_XOR_WriteProcessMemory_7314 {
  strings:
    $key_7314 = { 24 66 [2] 16 44 [2] 10 71 [2] 3e 71 [2] 01 6d }

  condition:
    any of them
}