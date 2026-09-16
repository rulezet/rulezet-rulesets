rule TTP_XOR_WriteProcessMemory_99b9 {
  strings:
    $key_99b9 = { ce cb [2] fc e9 [2] fa dc [2] d4 dc [2] eb c0 }

  condition:
    any of them
}