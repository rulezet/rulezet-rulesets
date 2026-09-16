rule TTP_XOR_WriteProcessMemory_99dc {
  strings:
    $key_99dc = { ce ae [2] fc 8c [2] fa b9 [2] d4 b9 [2] eb a5 }

  condition:
    any of them
}