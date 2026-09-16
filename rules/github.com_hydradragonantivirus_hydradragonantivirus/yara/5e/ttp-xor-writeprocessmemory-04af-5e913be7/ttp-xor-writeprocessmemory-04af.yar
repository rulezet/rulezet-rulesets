rule TTP_XOR_WriteProcessMemory_04af {
  strings:
    $key_04af = { 53 dd [2] 61 ff [2] 67 ca [2] 49 ca [2] 76 d6 }

  condition:
    any of them
}