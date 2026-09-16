rule TTP_XOR_WriteProcessMemory_5ea3 {
  strings:
    $key_5ea3 = { 09 d1 [2] 3b f3 [2] 3d c6 [2] 13 c6 [2] 2c da }

  condition:
    any of them
}