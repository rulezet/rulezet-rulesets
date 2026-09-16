rule TTP_XOR_WriteProcessMemory_2cdc {
  strings:
    $key_2cdc = { 7b ae [2] 49 8c [2] 4f b9 [2] 61 b9 [2] 5e a5 }

  condition:
    any of them
}