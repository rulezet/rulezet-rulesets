rule TTP_XOR_WriteProcessMemory_fb2f {
  strings:
    $key_fb2f = { ac 5d [2] 9e 7f [2] 98 4a [2] b6 4a [2] 89 56 }

  condition:
    any of them
}