rule TTP_XOR_WriteProcessMemory_5e94 {
  strings:
    $key_5e94 = { 09 e6 [2] 3b c4 [2] 3d f1 [2] 13 f1 [2] 2c ed }

  condition:
    any of them
}