rule TTP_XOR_WriteProcessMemory_0d9d {
  strings:
    $key_0d9d = { 5a ef [2] 68 cd [2] 6e f8 [2] 40 f8 [2] 7f e4 }

  condition:
    any of them
}