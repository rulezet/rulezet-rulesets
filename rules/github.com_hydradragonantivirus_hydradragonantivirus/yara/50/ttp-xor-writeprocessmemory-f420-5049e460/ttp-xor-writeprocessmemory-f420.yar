rule TTP_XOR_WriteProcessMemory_f420 {
  strings:
    $key_f420 = { a3 52 [2] 91 70 [2] 97 45 [2] b9 45 [2] 86 59 }

  condition:
    any of them
}