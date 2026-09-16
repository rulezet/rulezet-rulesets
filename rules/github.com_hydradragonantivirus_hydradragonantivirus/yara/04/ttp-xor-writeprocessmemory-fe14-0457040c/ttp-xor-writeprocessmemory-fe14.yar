rule TTP_XOR_WriteProcessMemory_fe14 {
  strings:
    $key_fe14 = { a9 66 [2] 9b 44 [2] 9d 71 [2] b3 71 [2] 8c 6d }

  condition:
    any of them
}