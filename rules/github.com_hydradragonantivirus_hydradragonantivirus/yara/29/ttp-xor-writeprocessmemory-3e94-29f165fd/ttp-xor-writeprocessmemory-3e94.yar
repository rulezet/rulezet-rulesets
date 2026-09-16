rule TTP_XOR_WriteProcessMemory_3e94 {
  strings:
    $key_3e94 = { 69 e6 [2] 5b c4 [2] 5d f1 [2] 73 f1 [2] 4c ed }

  condition:
    any of them
}