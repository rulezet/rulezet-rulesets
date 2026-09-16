rule TTP_XOR_WriteProcessMemory_31af {
  strings:
    $key_31af = { 66 dd [2] 54 ff [2] 52 ca [2] 7c ca [2] 43 d6 }

  condition:
    any of them
}