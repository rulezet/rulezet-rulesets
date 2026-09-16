rule TTP_XOR_WriteProcessMemory_fb24 {
  strings:
    $key_fb24 = { ac 56 [2] 9e 74 [2] 98 41 [2] b6 41 [2] 89 5d }

  condition:
    any of them
}