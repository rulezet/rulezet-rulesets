rule TTP_XOR_WriteProcessMemory_f4a8 {
  strings:
    $key_f4a8 = { a3 da [2] 91 f8 [2] 97 cd [2] b9 cd [2] 86 d1 }

  condition:
    any of them
}