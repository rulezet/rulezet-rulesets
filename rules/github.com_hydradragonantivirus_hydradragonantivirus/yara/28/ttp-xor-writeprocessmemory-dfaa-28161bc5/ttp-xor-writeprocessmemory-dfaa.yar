rule TTP_XOR_WriteProcessMemory_dfaa {
  strings:
    $key_dfaa = { 88 d8 [2] ba fa [2] bc cf [2] 92 cf [2] ad d3 }

  condition:
    any of them
}