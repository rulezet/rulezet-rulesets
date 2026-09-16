rule TTP_XOR_WriteProcessMemory_0c8d {
  strings:
    $key_0c8d = { 5b ff [2] 69 dd [2] 6f e8 [2] 41 e8 [2] 7e f4 }

  condition:
    any of them
}