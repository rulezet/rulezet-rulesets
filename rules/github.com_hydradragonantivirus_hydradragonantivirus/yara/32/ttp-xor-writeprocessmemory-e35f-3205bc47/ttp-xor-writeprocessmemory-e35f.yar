rule TTP_XOR_WriteProcessMemory_e35f {
  strings:
    $key_e35f = { b4 2d [2] 86 0f [2] 80 3a [2] ae 3a [2] 91 26 }

  condition:
    any of them
}