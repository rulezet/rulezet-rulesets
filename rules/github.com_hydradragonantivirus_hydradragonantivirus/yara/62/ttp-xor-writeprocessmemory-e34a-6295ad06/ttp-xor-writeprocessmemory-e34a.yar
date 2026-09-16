rule TTP_XOR_WriteProcessMemory_e34a {
  strings:
    $key_e34a = { b4 38 [2] 86 1a [2] 80 2f [2] ae 2f [2] 91 33 }

  condition:
    any of them
}