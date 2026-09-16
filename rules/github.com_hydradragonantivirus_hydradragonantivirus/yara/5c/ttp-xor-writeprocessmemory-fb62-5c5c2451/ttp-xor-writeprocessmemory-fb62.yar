rule TTP_XOR_WriteProcessMemory_fb62 {
  strings:
    $key_fb62 = { ac 10 [2] 9e 32 [2] 98 07 [2] b6 07 [2] 89 1b }

  condition:
    any of them
}