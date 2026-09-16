rule TTP_XOR_WriteProcessMemory_fb74 {
  strings:
    $key_fb74 = { ac 06 [2] 9e 24 [2] 98 11 [2] b6 11 [2] 89 0d }

  condition:
    any of them
}