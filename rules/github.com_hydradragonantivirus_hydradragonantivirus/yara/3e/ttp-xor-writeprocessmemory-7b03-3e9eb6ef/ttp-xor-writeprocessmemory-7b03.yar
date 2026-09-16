rule TTP_XOR_WriteProcessMemory_7b03 {
  strings:
    $key_7b03 = { 2c 71 [2] 1e 53 [2] 18 66 [2] 36 66 [2] 09 7a }

  condition:
    any of them
}