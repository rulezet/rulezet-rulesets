rule TTP_XOR_WriteProcessMemory_3648 {
  strings:
    $key_3648 = { 61 3a [2] 53 18 [2] 55 2d [2] 7b 2d [2] 44 31 }

  condition:
    any of them
}