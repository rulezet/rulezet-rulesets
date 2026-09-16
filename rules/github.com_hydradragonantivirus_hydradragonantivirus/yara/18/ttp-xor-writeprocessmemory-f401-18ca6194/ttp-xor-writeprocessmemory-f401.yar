rule TTP_XOR_WriteProcessMemory_f401 {
  strings:
    $key_f401 = { a3 73 [2] 91 51 [2] 97 64 [2] b9 64 [2] 86 78 }

  condition:
    any of them
}