rule TTP_XOR_WriteProcessMemory_e35a {
  strings:
    $key_e35a = { b4 28 [2] 86 0a [2] 80 3f [2] ae 3f [2] 91 23 }

  condition:
    any of them
}