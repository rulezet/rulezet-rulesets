rule TTP_XOR_WriteProcessMemory_368d {
  strings:
    $key_368d = { 61 ff [2] 53 dd [2] 55 e8 [2] 7b e8 [2] 44 f4 }

  condition:
    any of them
}