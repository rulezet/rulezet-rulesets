rule TTP_XOR_WriteProcessMemory_fb77 {
  strings:
    $key_fb77 = { ac 05 [2] 9e 27 [2] 98 12 [2] b6 12 [2] 89 0e }

  condition:
    any of them
}