rule TTP_XOR_WriteProcessMemory_e338 {
  strings:
    $key_e338 = { b4 4a [2] 86 68 [2] 80 5d [2] ae 5d [2] 91 41 }

  condition:
    any of them
}