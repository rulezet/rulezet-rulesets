rule TTP_XOR_WriteProcessMemory_e3b8 {
  strings:
    $key_e3b8 = { b4 ca [2] 86 e8 [2] 80 dd [2] ae dd [2] 91 c1 }

  condition:
    any of them
}