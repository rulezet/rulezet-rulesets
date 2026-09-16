rule TTP_XOR_WriteProcessMemory_2d9d {
  strings:
    $key_2d9d = { 7a ef [2] 48 cd [2] 4e f8 [2] 60 f8 [2] 5f e4 }

  condition:
    any of them
}