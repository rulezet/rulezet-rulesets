rule TTP_XOR_WriteProcessMemory_6eaf {
  strings:
    $key_6eaf = { 39 dd [2] 0b ff [2] 0d ca [2] 23 ca [2] 1c d6 }

  condition:
    any of them
}