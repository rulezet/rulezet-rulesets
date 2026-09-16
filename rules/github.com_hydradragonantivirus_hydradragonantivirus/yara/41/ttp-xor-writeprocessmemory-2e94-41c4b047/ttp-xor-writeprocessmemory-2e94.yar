rule TTP_XOR_WriteProcessMemory_2e94 {
  strings:
    $key_2e94 = { 79 e6 [2] 4b c4 [2] 4d f1 [2] 63 f1 [2] 5c ed }

  condition:
    any of them
}