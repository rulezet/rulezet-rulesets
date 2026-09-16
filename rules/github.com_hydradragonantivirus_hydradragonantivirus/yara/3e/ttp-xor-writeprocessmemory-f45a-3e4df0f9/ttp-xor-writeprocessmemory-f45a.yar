rule TTP_XOR_WriteProcessMemory_f45a {
  strings:
    $key_f45a = { a3 28 [2] 91 0a [2] 97 3f [2] b9 3f [2] 86 23 }

  condition:
    any of them
}