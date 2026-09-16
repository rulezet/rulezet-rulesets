rule TTP_XOR_WriteProcessMemory_43af {
  strings:
    $key_43af = { 14 dd [2] 26 ff [2] 20 ca [2] 0e ca [2] 31 d6 }

  condition:
    any of them
}