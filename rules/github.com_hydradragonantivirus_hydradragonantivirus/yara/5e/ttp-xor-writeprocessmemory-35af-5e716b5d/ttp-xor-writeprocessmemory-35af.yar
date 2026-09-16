rule TTP_XOR_WriteProcessMemory_35af {
  strings:
    $key_35af = { 62 dd [2] 50 ff [2] 56 ca [2] 78 ca [2] 47 d6 }

  condition:
    any of them
}