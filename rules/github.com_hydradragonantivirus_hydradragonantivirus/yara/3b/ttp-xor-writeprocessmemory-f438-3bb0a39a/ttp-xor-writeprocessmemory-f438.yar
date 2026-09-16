rule TTP_XOR_WriteProcessMemory_f438 {
  strings:
    $key_f438 = { a3 4a [2] 91 68 [2] 97 5d [2] b9 5d [2] 86 41 }

  condition:
    any of them
}