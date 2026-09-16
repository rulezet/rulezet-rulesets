rule TTP_XOR_WriteProcessMemory_0faf {
  strings:
    $key_0faf = { 58 dd [2] 6a ff [2] 6c ca [2] 42 ca [2] 7d d6 }

  condition:
    any of them
}