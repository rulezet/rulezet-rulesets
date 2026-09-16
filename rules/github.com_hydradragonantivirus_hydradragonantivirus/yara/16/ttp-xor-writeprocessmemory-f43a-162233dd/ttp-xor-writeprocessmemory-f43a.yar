rule TTP_XOR_WriteProcessMemory_f43a {
  strings:
    $key_f43a = { a3 48 [2] 91 6a [2] 97 5f [2] b9 5f [2] 86 43 }

  condition:
    any of them
}