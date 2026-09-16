rule TTP_XOR_WriteProcessMemory_7c8d {
  strings:
    $key_7c8d = { 2b ff [2] 19 dd [2] 1f e8 [2] 31 e8 [2] 0e f4 }

  condition:
    any of them
}