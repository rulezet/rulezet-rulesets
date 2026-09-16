rule TTP_XOR_WriteProcessMemory_c6c6 {
  strings:
    $key_c6c6 = { 91 b4 [2] a3 96 [2] a5 a3 [2] 8b a3 [2] b4 bf }

  condition:
    any of them
}