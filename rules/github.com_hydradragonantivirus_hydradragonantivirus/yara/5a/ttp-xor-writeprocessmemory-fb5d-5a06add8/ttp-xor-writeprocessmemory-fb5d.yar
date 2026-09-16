rule TTP_XOR_WriteProcessMemory_fb5d {
  strings:
    $key_fb5d = { ac 2f [2] 9e 0d [2] 98 38 [2] b6 38 [2] 89 24 }

  condition:
    any of them
}