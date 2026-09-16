rule TTP_XOR_WriteProcessMemory_22b8 {
  strings:
    $key_22b8 = { 75 ca [2] 47 e8 [2] 41 dd [2] 6f dd [2] 50 c1 }

  condition:
    any of them
}