rule TTP_XOR_WriteProcessMemory_cbaf {
  strings:
    $key_cbaf = { 9c dd [2] ae ff [2] a8 ca [2] 86 ca [2] b9 d6 }

  condition:
    any of them
}