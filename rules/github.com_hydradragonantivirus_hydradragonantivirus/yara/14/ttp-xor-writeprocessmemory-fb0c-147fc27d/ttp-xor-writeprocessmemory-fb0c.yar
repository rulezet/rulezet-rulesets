rule TTP_XOR_WriteProcessMemory_fb0c {
  strings:
    $key_fb0c = { ac 7e [2] 9e 5c [2] 98 69 [2] b6 69 [2] 89 75 }

  condition:
    any of them
}