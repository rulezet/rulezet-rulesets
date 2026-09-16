rule TTP_XOR_WriteProcessMemory_f9e8 {
  strings:
    $key_f9e8 = { ae 9a [2] 9c b8 [2] 9a 8d [2] b4 8d [2] 8b 91 }

  condition:
    any of them
}