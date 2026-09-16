rule TTP_XOR_WriteProcessMemory_3deb {
  strings:
    $key_3deb = { 6a 99 [2] 58 bb [2] 5e 8e [2] 70 8e [2] 4f 92 }

  condition:
    any of them
}