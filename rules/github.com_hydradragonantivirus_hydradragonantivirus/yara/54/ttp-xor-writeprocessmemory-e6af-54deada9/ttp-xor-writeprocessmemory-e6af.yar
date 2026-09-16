rule TTP_XOR_WriteProcessMemory_e6af {
  strings:
    $key_e6af = { b1 dd [2] 83 ff [2] 85 ca [2] ab ca [2] 94 d6 }

  condition:
    any of them
}