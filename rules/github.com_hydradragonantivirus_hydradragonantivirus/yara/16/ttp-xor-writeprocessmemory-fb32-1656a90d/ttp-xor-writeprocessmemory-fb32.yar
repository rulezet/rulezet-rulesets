rule TTP_XOR_WriteProcessMemory_fb32 {
  strings:
    $key_fb32 = { ac 40 [2] 9e 62 [2] 98 57 [2] b6 57 [2] 89 4b }

  condition:
    any of them
}