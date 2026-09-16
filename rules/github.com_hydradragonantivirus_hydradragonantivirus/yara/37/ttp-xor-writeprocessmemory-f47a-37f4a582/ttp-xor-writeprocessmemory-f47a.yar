rule TTP_XOR_WriteProcessMemory_f47a {
  strings:
    $key_f47a = { a3 08 [2] 91 2a [2] 97 1f [2] b9 1f [2] 86 03 }

  condition:
    any of them
}