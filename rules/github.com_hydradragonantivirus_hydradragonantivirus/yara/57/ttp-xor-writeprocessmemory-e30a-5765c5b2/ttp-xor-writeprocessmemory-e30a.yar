rule TTP_XOR_WriteProcessMemory_e30a {
  strings:
    $key_e30a = { b4 78 [2] 86 5a [2] 80 6f [2] ae 6f [2] 91 73 }

  condition:
    any of them
}