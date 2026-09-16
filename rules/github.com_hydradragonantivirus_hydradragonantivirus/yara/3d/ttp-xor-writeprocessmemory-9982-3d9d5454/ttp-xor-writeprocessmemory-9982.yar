rule TTP_XOR_WriteProcessMemory_9982 {
  strings:
    $key_9982 = { ce f0 [2] fc d2 [2] fa e7 [2] d4 e7 [2] eb fb }

  condition:
    any of them
}