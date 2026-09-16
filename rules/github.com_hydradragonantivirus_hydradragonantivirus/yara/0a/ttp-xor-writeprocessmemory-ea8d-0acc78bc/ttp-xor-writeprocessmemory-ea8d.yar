rule TTP_XOR_WriteProcessMemory_ea8d {
  strings:
    $key_ea8d = { bd ff [2] 8f dd [2] 89 e8 [2] a7 e8 [2] 98 f4 }

  condition:
    any of them
}