rule TTP_XOR_WriteProcessMemory_67af {
  strings:
    $key_67af = { 30 dd [2] 02 ff [2] 04 ca [2] 2a ca [2] 15 d6 }

  condition:
    any of them
}