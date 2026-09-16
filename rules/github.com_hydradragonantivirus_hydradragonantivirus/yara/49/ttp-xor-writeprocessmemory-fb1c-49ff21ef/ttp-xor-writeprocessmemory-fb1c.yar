rule TTP_XOR_WriteProcessMemory_fb1c {
  strings:
    $key_fb1c = { ac 6e [2] 9e 4c [2] 98 79 [2] b6 79 [2] 89 65 }

  condition:
    any of them
}