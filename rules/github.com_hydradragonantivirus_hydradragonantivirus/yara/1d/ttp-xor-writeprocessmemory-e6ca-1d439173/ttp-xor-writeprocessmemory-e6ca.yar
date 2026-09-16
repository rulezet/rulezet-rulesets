rule TTP_XOR_WriteProcessMemory_e6ca {
  strings:
    $key_e6ca = { b1 b8 [2] 83 9a [2] 85 af [2] ab af [2] 94 b3 }

  condition:
    any of them
}