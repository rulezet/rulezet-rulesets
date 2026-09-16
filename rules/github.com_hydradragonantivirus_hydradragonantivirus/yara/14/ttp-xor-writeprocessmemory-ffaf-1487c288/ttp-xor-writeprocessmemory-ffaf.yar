rule TTP_XOR_WriteProcessMemory_ffaf {
  strings:
    $key_ffaf = { a8 dd [2] 9a ff [2] 9c ca [2] b2 ca [2] 8d d6 }

  condition:
    any of them
}