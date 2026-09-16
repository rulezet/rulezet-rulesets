rule TTP_XOR_WriteProcessMemory_fe69 {
  strings:
    $key_fe69 = { a9 1b [2] 9b 39 [2] 9d 0c [2] b3 0c [2] 8c 10 }

  condition:
    any of them
}