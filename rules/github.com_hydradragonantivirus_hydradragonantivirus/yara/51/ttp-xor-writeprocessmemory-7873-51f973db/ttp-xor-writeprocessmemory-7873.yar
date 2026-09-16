rule TTP_XOR_WriteProcessMemory_7873 {
  strings:
    $key_7873 = { 2f 01 [2] 1d 23 [2] 1b 16 [2] 35 16 [2] 0a 0a }

  condition:
    any of them
}