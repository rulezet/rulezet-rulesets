rule TTP_XOR_WriteProcessMemory_f918 {
  strings:
    $key_f918 = { ae 6a [2] 9c 48 [2] 9a 7d [2] b4 7d [2] 8b 61 }

  condition:
    any of them
}