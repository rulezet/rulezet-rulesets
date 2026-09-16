rule TTP_XOR_WriteProcessMemory_fb06 {
  strings:
    $key_fb06 = { ac 74 [2] 9e 56 [2] 98 63 [2] b6 63 [2] 89 7f }

  condition:
    any of them
}