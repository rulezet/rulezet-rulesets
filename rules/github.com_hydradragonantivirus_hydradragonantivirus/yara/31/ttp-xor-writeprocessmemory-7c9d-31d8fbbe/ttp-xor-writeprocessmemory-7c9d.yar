rule TTP_XOR_WriteProcessMemory_7c9d {
  strings:
    $key_7c9d = { 2b ef [2] 19 cd [2] 1f f8 [2] 31 f8 [2] 0e e4 }

  condition:
    any of them
}