rule TTP_XOR_WriteProcessMemory_9986 {
  strings:
    $key_9986 = { ce f4 [2] fc d6 [2] fa e3 [2] d4 e3 [2] eb ff }

  condition:
    any of them
}