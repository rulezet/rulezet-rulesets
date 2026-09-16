rule TTP_XOR_WriteProcessMemory_4cb8 {
  strings:
    $key_4cb8 = { 1b ca [2] 29 e8 [2] 2f dd [2] 01 dd [2] 3e c1 }

  condition:
    any of them
}