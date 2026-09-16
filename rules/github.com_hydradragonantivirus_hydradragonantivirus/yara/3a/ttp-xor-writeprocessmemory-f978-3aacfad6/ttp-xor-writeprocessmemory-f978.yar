rule TTP_XOR_WriteProcessMemory_f978 {
  strings:
    $key_f978 = { ae 0a [2] 9c 28 [2] 9a 1d [2] b4 1d [2] 8b 01 }

  condition:
    any of them
}