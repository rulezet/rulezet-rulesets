rule TTP_XOR_WriteProcessMemory_fc9d {
  strings:
    $key_fc9d = { ab ef [2] 99 cd [2] 9f f8 [2] b1 f8 [2] 8e e4 }

  condition:
    any of them
}