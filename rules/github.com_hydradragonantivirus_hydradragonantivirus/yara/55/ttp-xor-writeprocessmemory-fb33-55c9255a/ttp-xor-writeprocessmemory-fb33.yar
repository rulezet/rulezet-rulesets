rule TTP_XOR_WriteProcessMemory_fb33 {
  strings:
    $key_fb33 = { ac 41 [2] 9e 63 [2] 98 56 [2] b6 56 [2] 89 4a }

  condition:
    any of them
}