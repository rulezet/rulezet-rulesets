rule TTP_XOR_WriteProcessMemory_fa8d {
  strings:
    $key_fa8d = { ad ff [2] 9f dd [2] 99 e8 [2] b7 e8 [2] 88 f4 }

  condition:
    any of them
}