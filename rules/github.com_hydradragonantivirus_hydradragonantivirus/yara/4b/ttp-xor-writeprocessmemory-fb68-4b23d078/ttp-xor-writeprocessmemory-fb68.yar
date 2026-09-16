rule TTP_XOR_WriteProcessMemory_fb68 {
  strings:
    $key_fb68 = { ac 1a [2] 9e 38 [2] 98 0d [2] b6 0d [2] 89 11 }

  condition:
    any of them
}