rule TTP_XOR_WriteProcessMemory_fb0f {
  strings:
    $key_fb0f = { ac 7d [2] 9e 5f [2] 98 6a [2] b6 6a [2] 89 76 }

  condition:
    any of them
}