rule TTP_XOR_WriteProcessMemory_cdaf {
  strings:
    $key_cdaf = { 9a dd [2] a8 ff [2] ae ca [2] 80 ca [2] bf d6 }

  condition:
    any of them
}