rule TTP_XOR_WriteProcessMemory_fe64 {
  strings:
    $key_fe64 = { a9 16 [2] 9b 34 [2] 9d 01 [2] b3 01 [2] 8c 1d }

  condition:
    any of them
}