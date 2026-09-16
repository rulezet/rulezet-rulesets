rule TTP_XOR_WriteProcessMemory_00c6 {
  strings:
    $key_00c6 = { 57 b4 [2] 65 96 [2] 63 a3 [2] 4d a3 [2] 72 bf }

  condition:
    any of them
}