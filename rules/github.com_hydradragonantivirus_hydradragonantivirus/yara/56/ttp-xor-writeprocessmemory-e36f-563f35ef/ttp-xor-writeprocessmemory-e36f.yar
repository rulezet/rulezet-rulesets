rule TTP_XOR_WriteProcessMemory_e36f {
  strings:
    $key_e36f = { b4 1d [2] 86 3f [2] 80 0a [2] ae 0a [2] 91 16 }

  condition:
    any of them
}