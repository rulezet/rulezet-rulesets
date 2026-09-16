rule TTP_XOR_WriteProcessMemory_fb03 {
  strings:
    $key_fb03 = { ac 71 [2] 9e 53 [2] 98 66 [2] b6 66 [2] 89 7a }

  condition:
    any of them
}