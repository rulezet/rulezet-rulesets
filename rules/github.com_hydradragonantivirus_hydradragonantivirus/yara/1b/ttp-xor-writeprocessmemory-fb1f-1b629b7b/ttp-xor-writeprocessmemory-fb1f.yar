rule TTP_XOR_WriteProcessMemory_fb1f {
  strings:
    $key_fb1f = { ac 6d [2] 9e 4f [2] 98 7a [2] b6 7a [2] 89 66 }

  condition:
    any of them
}