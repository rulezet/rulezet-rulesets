rule TTP_XOR_WriteProcessMemory_02af {
  strings:
    $key_02af = { 55 dd [2] 67 ff [2] 61 ca [2] 4f ca [2] 70 d6 }

  condition:
    any of them
}