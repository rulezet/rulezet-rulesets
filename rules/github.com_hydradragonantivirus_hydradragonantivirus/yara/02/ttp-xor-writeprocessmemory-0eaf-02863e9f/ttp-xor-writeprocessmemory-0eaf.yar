rule TTP_XOR_WriteProcessMemory_0eaf {
  strings:
    $key_0eaf = { 59 dd [2] 6b ff [2] 6d ca [2] 43 ca [2] 7c d6 }

  condition:
    any of them
}