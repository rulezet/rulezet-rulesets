rule TTP_XOR_WriteProcessMemory_f2bf {
  strings:
    $key_f2bf = { a5 cd [2] 97 ef [2] 91 da [2] bf da [2] 80 c6 }

  condition:
    any of them
}