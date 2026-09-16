rule TTP_XOR_WriteProcessMemory_fe0c {
  strings:
    $key_fe0c = { a9 7e [2] 9b 5c [2] 9d 69 [2] b3 69 [2] 8c 75 }

  condition:
    any of them
}