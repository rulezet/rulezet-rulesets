rule TTP_XOR_WriteProcessMemory_fb5a {
  strings:
    $key_fb5a = { ac 28 [2] 9e 0a [2] 98 3f [2] b6 3f [2] 89 23 }

  condition:
    any of them
}