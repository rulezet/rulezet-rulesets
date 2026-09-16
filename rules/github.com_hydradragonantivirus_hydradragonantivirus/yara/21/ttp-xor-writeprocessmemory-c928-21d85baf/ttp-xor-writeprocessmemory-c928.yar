rule TTP_XOR_WriteProcessMemory_c928 {
  strings:
    $key_c928 = { 9e 5a [2] ac 78 [2] aa 4d [2] 84 4d [2] bb 51 }

  condition:
    any of them
}