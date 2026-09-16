rule TTP_XOR_WriteProcessMemory_2c83 {
  strings:
    $key_2c83 = { 7b f1 [2] 49 d3 [2] 4f e6 [2] 61 e6 [2] 5e fa }

  condition:
    any of them
}