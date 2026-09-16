rule TTP_XOR_WriteProcessMemory_3d9a {
  strings:
    $key_3d9a = { 6a e8 [2] 58 ca [2] 5e ff [2] 70 ff [2] 4f e3 }

  condition:
    any of them
}