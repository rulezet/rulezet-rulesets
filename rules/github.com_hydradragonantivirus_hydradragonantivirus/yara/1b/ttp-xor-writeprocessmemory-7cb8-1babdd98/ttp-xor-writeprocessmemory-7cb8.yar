rule TTP_XOR_WriteProcessMemory_7cb8 {
  strings:
    $key_7cb8 = { 2b ca [2] 19 e8 [2] 1f dd [2] 31 dd [2] 0e c1 }

  condition:
    any of them
}