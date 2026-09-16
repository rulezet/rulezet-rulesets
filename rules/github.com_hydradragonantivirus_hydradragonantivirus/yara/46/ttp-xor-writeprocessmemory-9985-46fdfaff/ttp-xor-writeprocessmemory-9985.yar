rule TTP_XOR_WriteProcessMemory_9985 {
  strings:
    $key_9985 = { ce f7 [2] fc d5 [2] fa e0 [2] d4 e0 [2] eb fc }

  condition:
    any of them
}