rule TTP_XOR_WriteProcessMemory_fdaa {
  strings:
    $key_fdaa = { aa d8 [2] 98 fa [2] 9e cf [2] b0 cf [2] 8f d3 }

  condition:
    any of them
}