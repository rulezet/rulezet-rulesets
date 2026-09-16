rule TTP_XOR_WriteProcessMemory_399f {
  strings:
    $key_399f = { 6e ed [2] 5c cf [2] 5a fa [2] 74 fa [2] 4b e6 }

  condition:
    any of them
}