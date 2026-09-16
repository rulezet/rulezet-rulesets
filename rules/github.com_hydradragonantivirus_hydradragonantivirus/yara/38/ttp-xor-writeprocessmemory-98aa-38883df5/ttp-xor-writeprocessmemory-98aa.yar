rule TTP_XOR_WriteProcessMemory_98aa {
  strings:
    $key_98aa = { cf d8 [2] fd fa [2] fb cf [2] d5 cf [2] ea d3 }

  condition:
    any of them
}