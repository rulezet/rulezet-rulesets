rule TTP_XOR_WriteProcessMemory_4e94 {
  strings:
    $key_4e94 = { 19 e6 [2] 2b c4 [2] 2d f1 [2] 03 f1 [2] 3c ed }

  condition:
    any of them
}