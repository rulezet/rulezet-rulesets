rule TTP_XOR_WriteProcessMemory_f444 {
  strings:
    $key_f444 = { a3 36 [2] 91 14 [2] 97 21 [2] b9 21 [2] 86 3d }

  condition:
    any of them
}