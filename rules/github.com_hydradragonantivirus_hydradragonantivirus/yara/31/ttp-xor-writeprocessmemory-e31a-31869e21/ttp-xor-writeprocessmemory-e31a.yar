rule TTP_XOR_WriteProcessMemory_e31a {
  strings:
    $key_e31a = { b4 68 [2] 86 4a [2] 80 7f [2] ae 7f [2] 91 63 }

  condition:
    any of them
}