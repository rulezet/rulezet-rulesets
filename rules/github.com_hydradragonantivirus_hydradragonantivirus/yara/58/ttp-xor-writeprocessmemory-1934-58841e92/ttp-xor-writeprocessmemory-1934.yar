rule TTP_XOR_WriteProcessMemory_1934 {
  strings:
    $key_1934 = { 4e 46 [2] 7c 64 [2] 7a 51 [2] 54 51 [2] 6b 4d }

  condition:
    any of them
}