rule TTP_XOR_WriteProcessMemory_36af {
  strings:
    $key_36af = { 61 dd [2] 53 ff [2] 55 ca [2] 7b ca [2] 44 d6 }

  condition:
    any of them
}