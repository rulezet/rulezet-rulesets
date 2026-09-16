rule TTP_XOR_WriteProcessMemory_2df4 {
  strings:
    $key_2df4 = { 7a 86 [2] 48 a4 [2] 4e 91 [2] 60 91 [2] 5f 8d }

  condition:
    any of them
}