rule TTP_XOR_WriteProcessMemory_daaf {
  strings:
    $key_daaf = { 8d dd [2] bf ff [2] b9 ca [2] 97 ca [2] a8 d6 }

  condition:
    any of them
}