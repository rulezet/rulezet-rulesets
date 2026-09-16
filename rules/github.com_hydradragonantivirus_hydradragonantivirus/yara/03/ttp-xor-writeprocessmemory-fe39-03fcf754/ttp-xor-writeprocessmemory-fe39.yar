rule TTP_XOR_WriteProcessMemory_fe39 {
  strings:
    $key_fe39 = { a9 4b [2] 9b 69 [2] 9d 5c [2] b3 5c [2] 8c 40 }

  condition:
    any of them
}