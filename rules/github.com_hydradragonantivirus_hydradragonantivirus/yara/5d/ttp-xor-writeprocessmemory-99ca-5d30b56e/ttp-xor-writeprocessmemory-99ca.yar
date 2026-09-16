rule TTP_XOR_WriteProcessMemory_99ca {
  strings:
    $key_99ca = { ce b8 [2] fc 9a [2] fa af [2] d4 af [2] eb b3 }

  condition:
    any of them
}