rule TTP_XOR_WriteProcessMemory_fb27 {
  strings:
    $key_fb27 = { ac 55 [2] 9e 77 [2] 98 42 [2] b6 42 [2] 89 5e }

  condition:
    any of them
}