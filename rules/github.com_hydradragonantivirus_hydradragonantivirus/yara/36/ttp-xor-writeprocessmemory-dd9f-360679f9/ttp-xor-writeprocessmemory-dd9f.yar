rule TTP_XOR_WriteProcessMemory_dd9f {
  strings:
    $key_dd9f = { 8a ed [2] b8 cf [2] be fa [2] 90 fa [2] af e6 }

  condition:
    any of them
}