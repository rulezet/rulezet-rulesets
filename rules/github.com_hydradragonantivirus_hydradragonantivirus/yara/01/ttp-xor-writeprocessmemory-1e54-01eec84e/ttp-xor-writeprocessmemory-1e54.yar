rule TTP_XOR_WriteProcessMemory_1e54 {
  strings:
    $key_1e54 = { 49 26 [2] 7b 04 [2] 7d 31 [2] 53 31 [2] 6c 2d }

  condition:
    any of them
}