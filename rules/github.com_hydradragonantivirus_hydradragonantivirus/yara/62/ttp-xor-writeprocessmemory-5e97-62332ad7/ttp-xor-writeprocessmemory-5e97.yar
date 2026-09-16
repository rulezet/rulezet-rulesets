rule TTP_XOR_WriteProcessMemory_5e97 {
  strings:
    $key_5e97 = { 09 e5 [2] 3b c7 [2] 3d f2 [2] 13 f2 [2] 2c ee }

  condition:
    any of them
}