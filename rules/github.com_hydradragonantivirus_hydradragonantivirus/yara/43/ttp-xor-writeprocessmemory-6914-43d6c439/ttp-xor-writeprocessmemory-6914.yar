rule TTP_XOR_WriteProcessMemory_6914 {
  strings:
    $key_6914 = { 3e 66 [2] 0c 44 [2] 0a 71 [2] 24 71 [2] 1b 6d }

  condition:
    any of them
}