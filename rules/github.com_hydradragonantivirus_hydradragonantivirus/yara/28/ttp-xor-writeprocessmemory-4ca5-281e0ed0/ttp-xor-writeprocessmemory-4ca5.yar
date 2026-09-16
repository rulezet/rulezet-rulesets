rule TTP_XOR_WriteProcessMemory_4ca5 {
  strings:
    $key_4ca5 = { 1b d7 [2] 29 f5 [2] 2f c0 [2] 01 c0 [2] 3e dc }

  condition:
    any of them
}