rule TTP_XOR_WriteProcessMemory_e28d {
  strings:
    $key_e28d = { b5 ff [2] 87 dd [2] 81 e8 [2] af e8 [2] 90 f4 }

  condition:
    any of them
}