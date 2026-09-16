rule TTP_XOR_WriteProcessMemory_fb54 {
  strings:
    $key_fb54 = { ac 26 [2] 9e 04 [2] 98 31 [2] b6 31 [2] 89 2d }

  condition:
    any of them
}