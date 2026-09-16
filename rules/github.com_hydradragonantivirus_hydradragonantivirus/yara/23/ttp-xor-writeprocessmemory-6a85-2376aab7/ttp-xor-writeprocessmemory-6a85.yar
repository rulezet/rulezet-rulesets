rule TTP_XOR_WriteProcessMemory_6a85 {
  strings:
    $key_6a85 = { 3d f7 [2] 0f d5 [2] 09 e0 [2] 27 e0 [2] 18 fc }

  condition:
    any of them
}