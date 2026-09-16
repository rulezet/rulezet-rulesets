rule TTP_XOR_WriteProcessMemory_fb5f {
  strings:
    $key_fb5f = { ac 2d [2] 9e 0f [2] 98 3a [2] b6 3a [2] 89 26 }

  condition:
    any of them
}