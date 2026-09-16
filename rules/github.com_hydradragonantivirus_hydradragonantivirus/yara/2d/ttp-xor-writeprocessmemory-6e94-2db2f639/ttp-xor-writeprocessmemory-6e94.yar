rule TTP_XOR_WriteProcessMemory_6e94 {
  strings:
    $key_6e94 = { 39 e6 [2] 0b c4 [2] 0d f1 [2] 23 f1 [2] 1c ed }

  condition:
    any of them
}