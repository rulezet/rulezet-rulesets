rule TTP_XOR_WriteProcessMemory_fe54 {
  strings:
    $key_fe54 = { a9 26 [2] 9b 04 [2] 9d 31 [2] b3 31 [2] 8c 2d }

  condition:
    any of them
}