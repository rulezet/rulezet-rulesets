rule TTP_XOR_WriteProcessMemory_e32f {
  strings:
    $key_e32f = { b4 5d [2] 86 7f [2] 80 4a [2] ae 4a [2] 91 56 }

  condition:
    any of them
}