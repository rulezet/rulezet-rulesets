rule TTP_XOR_WriteProcessMemory_7ac6 {
  strings:
    $key_7ac6 = { 2d b4 [2] 1f 96 [2] 19 a3 [2] 37 a3 [2] 08 bf }

  condition:
    any of them
}