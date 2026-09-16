rule TTP_XOR_WriteProcessMemory_fe5c {
  strings:
    $key_fe5c = { a9 2e [2] 9b 0c [2] 9d 39 [2] b3 39 [2] 8c 25 }

  condition:
    any of them
}