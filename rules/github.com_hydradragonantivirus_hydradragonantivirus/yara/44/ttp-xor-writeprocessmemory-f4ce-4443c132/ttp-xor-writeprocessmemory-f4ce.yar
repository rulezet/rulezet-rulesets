rule TTP_XOR_WriteProcessMemory_f4ce {
  strings:
    $key_f4ce = { a3 bc [2] 91 9e [2] 97 ab [2] b9 ab [2] 86 b7 }

  condition:
    any of them
}