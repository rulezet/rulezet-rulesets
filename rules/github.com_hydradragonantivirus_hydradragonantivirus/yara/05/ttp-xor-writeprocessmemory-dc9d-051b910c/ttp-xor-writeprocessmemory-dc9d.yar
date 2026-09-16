rule TTP_XOR_WriteProcessMemory_dc9d {
  strings:
    $key_dc9d = { 8b ef [2] b9 cd [2] bf f8 [2] 91 f8 [2] ae e4 }

  condition:
    any of them
}