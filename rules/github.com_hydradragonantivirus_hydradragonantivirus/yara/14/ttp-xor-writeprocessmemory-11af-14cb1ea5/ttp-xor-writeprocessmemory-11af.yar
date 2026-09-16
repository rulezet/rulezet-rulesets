rule TTP_XOR_WriteProcessMemory_11af {
  strings:
    $key_11af = { 46 dd [2] 74 ff [2] 72 ca [2] 5c ca [2] 63 d6 }

  condition:
    any of them
}