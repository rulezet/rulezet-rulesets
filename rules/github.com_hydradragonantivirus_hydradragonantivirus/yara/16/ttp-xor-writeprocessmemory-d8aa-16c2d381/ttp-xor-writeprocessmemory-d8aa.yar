rule TTP_XOR_WriteProcessMemory_d8aa {
  strings:
    $key_d8aa = { 8f d8 [2] bd fa [2] bb cf [2] 95 cf [2] aa d3 }

  condition:
    any of them
}