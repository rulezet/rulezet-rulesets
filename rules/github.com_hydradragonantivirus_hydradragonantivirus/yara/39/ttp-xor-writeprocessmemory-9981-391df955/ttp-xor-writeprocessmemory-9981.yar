rule TTP_XOR_WriteProcessMemory_9981 {
  strings:
    $key_9981 = { ce f3 [2] fc d1 [2] fa e4 [2] d4 e4 [2] eb f8 }

  condition:
    any of them
}