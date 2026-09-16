rule TTP_XOR_WriteProcessMemory_f454 {
  strings:
    $key_f454 = { a3 26 [2] 91 04 [2] 97 31 [2] b9 31 [2] 86 2d }

  condition:
    any of them
}