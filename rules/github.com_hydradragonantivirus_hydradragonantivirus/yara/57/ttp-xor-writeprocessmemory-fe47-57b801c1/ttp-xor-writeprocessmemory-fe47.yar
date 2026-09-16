rule TTP_XOR_WriteProcessMemory_fe47 {
  strings:
    $key_fe47 = { a9 35 [2] 9b 17 [2] 9d 22 [2] b3 22 [2] 8c 3e }

  condition:
    any of them
}