rule TTP_XOR_WriteProcessMemory_fb64 {
  strings:
    $key_fb64 = { ac 16 [2] 9e 34 [2] 98 01 [2] b6 01 [2] 89 1d }

  condition:
    any of them
}