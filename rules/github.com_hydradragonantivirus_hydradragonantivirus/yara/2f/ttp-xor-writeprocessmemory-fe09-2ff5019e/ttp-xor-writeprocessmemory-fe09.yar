rule TTP_XOR_WriteProcessMemory_fe09 {
  strings:
    $key_fe09 = { a9 7b [2] 9b 59 [2] 9d 6c [2] b3 6c [2] 8c 70 }

  condition:
    any of them
}