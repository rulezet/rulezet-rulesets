rule TTP_XOR_WriteProcessMemory_f44f {
  strings:
    $key_f44f = { a3 3d [2] 91 1f [2] 97 2a [2] b9 2a [2] 86 36 }

  condition:
    any of them
}