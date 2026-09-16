rule TTP_XOR_WriteProcessMemory_efc1 {
  strings:
    $key_efc1 = { b8 b3 [2] 8a 91 [2] 8c a4 [2] a2 a4 [2] 9d b8 }

  condition:
    any of them
}