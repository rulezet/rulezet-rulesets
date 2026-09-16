rule TTP_XOR_WriteProcessMemory_fb5c {
  strings:
    $key_fb5c = { ac 2e [2] 9e 0c [2] 98 39 [2] b6 39 [2] 89 25 }

  condition:
    any of them
}