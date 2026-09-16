rule TTP_XOR_WriteProcessMemory_f4c8 {
  strings:
    $key_f4c8 = { a3 ba [2] 91 98 [2] 97 ad [2] b9 ad [2] 86 b1 }

  condition:
    any of them
}