rule TTP_XOR_WriteProcessMemory_f411 {
  strings:
    $key_f411 = { a3 63 [2] 91 41 [2] 97 74 [2] b9 74 [2] 86 68 }

  condition:
    any of them
}