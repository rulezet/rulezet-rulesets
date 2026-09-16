rule TTP_XOR_WriteProcessMemory_fb22 {
  strings:
    $key_fb22 = { ac 50 [2] 9e 72 [2] 98 47 [2] b6 47 [2] 89 5b }

  condition:
    any of them
}