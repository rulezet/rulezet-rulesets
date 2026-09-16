rule TTP_XOR_WriteProcessMemory_e37f {
  strings:
    $key_e37f = { b4 0d [2] 86 2f [2] 80 1a [2] ae 1a [2] 91 06 }

  condition:
    any of them
}