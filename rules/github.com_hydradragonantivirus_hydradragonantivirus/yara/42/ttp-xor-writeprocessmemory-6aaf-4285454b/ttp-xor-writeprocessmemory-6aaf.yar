rule TTP_XOR_WriteProcessMemory_6aaf {
  strings:
    $key_6aaf = { 3d dd [2] 0f ff [2] 09 ca [2] 27 ca [2] 18 d6 }

  condition:
    any of them
}