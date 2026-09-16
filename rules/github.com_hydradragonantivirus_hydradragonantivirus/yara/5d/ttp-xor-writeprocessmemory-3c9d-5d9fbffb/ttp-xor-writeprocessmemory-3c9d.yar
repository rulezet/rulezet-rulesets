rule TTP_XOR_WriteProcessMemory_3c9d {
  strings:
    $key_3c9d = { 6b ef [2] 59 cd [2] 5f f8 [2] 71 f8 [2] 4e e4 }

  condition:
    any of them
}