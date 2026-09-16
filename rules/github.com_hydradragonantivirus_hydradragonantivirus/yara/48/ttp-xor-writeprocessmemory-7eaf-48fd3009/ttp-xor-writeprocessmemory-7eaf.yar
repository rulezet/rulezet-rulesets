rule TTP_XOR_WriteProcessMemory_7eaf {
  strings:
    $key_7eaf = { 29 dd [2] 1b ff [2] 1d ca [2] 33 ca [2] 0c d6 }

  condition:
    any of them
}