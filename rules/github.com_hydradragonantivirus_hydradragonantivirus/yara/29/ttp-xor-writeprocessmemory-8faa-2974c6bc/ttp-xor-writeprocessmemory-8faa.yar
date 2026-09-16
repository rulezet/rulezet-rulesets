rule TTP_XOR_WriteProcessMemory_8faa {
  strings:
    $key_8faa = { d8 d8 [2] ea fa [2] ec cf [2] c2 cf [2] fd d3 }

  condition:
    any of them
}