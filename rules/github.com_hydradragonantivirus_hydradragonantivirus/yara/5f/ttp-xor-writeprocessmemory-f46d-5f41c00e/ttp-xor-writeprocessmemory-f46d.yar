rule TTP_XOR_WriteProcessMemory_f46d {
  strings:
    $key_f46d = { a3 1f [2] 91 3d [2] 97 08 [2] b9 08 [2] 86 14 }

  condition:
    any of them
}