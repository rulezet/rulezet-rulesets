rule TTP_XOR_WriteProcessMemory_e36a {
  strings:
    $key_e36a = { b4 18 [2] 86 3a [2] 80 0f [2] ae 0f [2] 91 13 }

  condition:
    any of them
}