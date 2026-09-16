rule TTP_XOR_WriteProcessMemory_6bbd {
  strings:
    $key_6bbd = { 3c cf [2] 0e ed [2] 08 d8 [2] 26 d8 [2] 19 c4 }

  condition:
    any of them
}