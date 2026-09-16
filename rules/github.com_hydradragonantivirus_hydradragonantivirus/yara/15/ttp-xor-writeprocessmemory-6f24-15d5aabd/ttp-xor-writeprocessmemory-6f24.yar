rule TTP_XOR_WriteProcessMemory_6f24 {
  strings:
    $key_6f24 = { 38 56 [2] 0a 74 [2] 0c 41 [2] 22 41 [2] 1d 5d }

  condition:
    any of them
}