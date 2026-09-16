rule TTP_XOR_WriteProcessMemory_9984 {
  strings:
    $key_9984 = { ce f6 [2] fc d4 [2] fa e1 [2] d4 e1 [2] eb fd }

  condition:
    any of them
}