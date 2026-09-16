rule TTP_XOR_WriteProcessMemory_eac6 {
  strings:
    $key_eac6 = { bd b4 [2] 8f 96 [2] 89 a3 [2] a7 a3 [2] 98 bf }

  condition:
    any of them
}