rule TTP_XOR_WriteProcessMemory_e3e5 {
  strings:
    $key_e3e5 = { b4 97 [2] 86 b5 [2] 80 80 [2] ae 80 [2] 91 9c }

  condition:
    any of them
}