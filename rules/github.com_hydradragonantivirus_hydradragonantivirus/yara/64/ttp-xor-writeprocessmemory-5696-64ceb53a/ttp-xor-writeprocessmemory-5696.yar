rule TTP_XOR_WriteProcessMemory_5696 {
  strings:
    $key_5696 = { 01 e4 [2] 33 c6 [2] 35 f3 [2] 1b f3 [2] 24 ef }

  condition:
    any of them
}