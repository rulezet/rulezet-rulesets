rule TTP_XOR_WriteProcessMemory_4c83 {
  strings:
    $key_4c83 = { 1b f1 [2] 29 d3 [2] 2f e6 [2] 01 e6 [2] 3e fa }

  condition:
    any of them
}