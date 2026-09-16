rule TTP_XOR_WriteProcessMemory_6c87 {
  strings:
    $key_6c87 = { 3b f5 [2] 09 d7 [2] 0f e2 [2] 21 e2 [2] 1e fe }

  condition:
    any of them
}