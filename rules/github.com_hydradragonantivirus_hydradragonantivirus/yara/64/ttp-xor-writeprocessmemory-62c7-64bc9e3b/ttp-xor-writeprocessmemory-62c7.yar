rule TTP_XOR_WriteProcessMemory_62c7 {
  strings:
    $key_62c7 = { 35 b5 [2] 07 97 [2] 01 a2 [2] 2f a2 [2] 10 be }

  condition:
    any of them
}