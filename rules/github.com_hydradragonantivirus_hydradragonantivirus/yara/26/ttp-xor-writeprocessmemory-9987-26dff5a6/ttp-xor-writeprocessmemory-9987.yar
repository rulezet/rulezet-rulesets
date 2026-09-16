rule TTP_XOR_WriteProcessMemory_9987 {
  strings:
    $key_9987 = { ce f5 [2] fc d7 [2] fa e2 [2] d4 e2 [2] eb fe }

  condition:
    any of them
}