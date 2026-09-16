rule TTP_XOR_WriteProcessMemory_e3e8 {
  strings:
    $key_e3e8 = { b4 9a [2] 86 b8 [2] 80 8d [2] ae 8d [2] 91 91 }

  condition:
    any of them
}