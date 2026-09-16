rule TTP_XOR_WriteProcessMemory_6cb8 {
  strings:
    $key_6cb8 = { 3b ca [2] 09 e8 [2] 0f dd [2] 21 dd [2] 1e c1 }

  condition:
    any of them
}