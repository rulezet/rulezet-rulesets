rule TTP_XOR_WriteProcessMemory_e308 {
  strings:
    $key_e308 = { b4 7a [2] 86 58 [2] 80 6d [2] ae 6d [2] 91 71 }

  condition:
    any of them
}