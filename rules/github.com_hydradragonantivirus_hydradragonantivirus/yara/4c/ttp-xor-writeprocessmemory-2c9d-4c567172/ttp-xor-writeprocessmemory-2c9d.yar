rule TTP_XOR_WriteProcessMemory_2c9d {
  strings:
    $key_2c9d = { 7b ef [2] 49 cd [2] 4f f8 [2] 61 f8 [2] 5e e4 }

  condition:
    any of them
}