rule TTP_XOR_WriteProcessMemory_fb47 {
  strings:
    $key_fb47 = { ac 35 [2] 9e 17 [2] 98 22 [2] b6 22 [2] 89 3e }

  condition:
    any of them
}