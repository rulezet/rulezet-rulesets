rule TTP_XOR_WriteProcessMemory_7aaf {
  strings:
    $key_7aaf = { 2d dd [2] 1f ff [2] 19 ca [2] 37 ca [2] 08 d6 }

  condition:
    any of them
}