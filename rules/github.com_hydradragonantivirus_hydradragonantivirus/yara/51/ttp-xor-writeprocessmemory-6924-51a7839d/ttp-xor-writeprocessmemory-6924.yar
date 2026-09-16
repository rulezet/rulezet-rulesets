rule TTP_XOR_WriteProcessMemory_6924 {
  strings:
    $key_6924 = { 3e 56 [2] 0c 74 [2] 0a 41 [2] 24 41 [2] 1b 5d }

  condition:
    any of them
}