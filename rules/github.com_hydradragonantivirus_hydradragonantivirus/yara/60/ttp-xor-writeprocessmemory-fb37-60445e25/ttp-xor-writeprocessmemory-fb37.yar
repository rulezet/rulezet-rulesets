rule TTP_XOR_WriteProcessMemory_fb37 {
  strings:
    $key_fb37 = { ac 45 [2] 9e 67 [2] 98 52 [2] b6 52 [2] 89 4e }

  condition:
    any of them
}