rule TTP_XOR_WriteProcessMemory_3934 {
  strings:
    $key_3934 = { 6e 46 [2] 5c 64 [2] 5a 51 [2] 74 51 [2] 4b 4d }

  condition:
    any of them
}