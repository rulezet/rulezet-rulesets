rule TTP_XOR_WriteProcessMemory_1faf {
  strings:
    $key_1faf = { 48 dd [2] 7a ff [2] 7c ca [2] 52 ca [2] 6d d6 }

  condition:
    any of them
}