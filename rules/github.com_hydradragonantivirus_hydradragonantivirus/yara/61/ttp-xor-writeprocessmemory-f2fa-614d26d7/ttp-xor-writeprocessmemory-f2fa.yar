rule TTP_XOR_WriteProcessMemory_f2fa {
  strings:
    $key_f2fa = { a5 88 [2] 97 aa [2] 91 9f [2] bf 9f [2] 80 83 }

  condition:
    any of them
}