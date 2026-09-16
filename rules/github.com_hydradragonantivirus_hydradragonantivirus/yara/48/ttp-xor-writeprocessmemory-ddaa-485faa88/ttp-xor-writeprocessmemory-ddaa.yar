rule TTP_XOR_WriteProcessMemory_ddaa {
  strings:
    $key_ddaa = { 8a d8 [2] b8 fa [2] be cf [2] 90 cf [2] af d3 }

  condition:
    any of them
}