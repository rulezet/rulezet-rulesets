rule TTP_XOR_WriteProcessMemory_f47d {
  strings:
    $key_f47d = { a3 0f [2] 91 2d [2] 97 18 [2] b9 18 [2] 86 04 }

  condition:
    any of them
}