rule TTP_XOR_WriteProcessMemory_1954 {
  strings:
    $key_1954 = { 4e 26 [2] 7c 04 [2] 7a 31 [2] 54 31 [2] 6b 2d }

  condition:
    any of them
}