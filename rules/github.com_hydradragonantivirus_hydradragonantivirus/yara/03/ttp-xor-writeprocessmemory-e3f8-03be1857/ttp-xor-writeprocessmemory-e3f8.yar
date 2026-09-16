rule TTP_XOR_WriteProcessMemory_e3f8 {
  strings:
    $key_e3f8 = { b4 8a [2] 86 a8 [2] 80 9d [2] ae 9d [2] 91 81 }

  condition:
    any of them
}