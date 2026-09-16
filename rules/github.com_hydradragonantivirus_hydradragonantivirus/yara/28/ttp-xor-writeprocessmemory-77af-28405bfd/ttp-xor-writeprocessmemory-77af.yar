rule TTP_XOR_WriteProcessMemory_77af {
  strings:
    $key_77af = { 20 dd [2] 12 ff [2] 14 ca [2] 3a ca [2] 05 d6 }

  condition:
    any of them
}