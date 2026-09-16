rule TTP_XOR_WriteProcessMemory_f2ff {
  strings:
    $key_f2ff = { a5 8d [2] 97 af [2] 91 9a [2] bf 9a [2] 80 86 }

  condition:
    any of them
}