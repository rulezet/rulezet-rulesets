rule TTP_XOR_WriteProcessMemory_f4bf {
  strings:
    $key_f4bf = { a3 cd [2] 91 ef [2] 97 da [2] b9 da [2] 86 c6 }

  condition:
    any of them
}