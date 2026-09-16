rule TTP_XOR_WriteProcessMemory_5c83 {
  strings:
    $key_5c83 = { 0b f1 [2] 39 d3 [2] 3f e6 [2] 11 e6 [2] 2e fa }

  condition:
    any of them
}