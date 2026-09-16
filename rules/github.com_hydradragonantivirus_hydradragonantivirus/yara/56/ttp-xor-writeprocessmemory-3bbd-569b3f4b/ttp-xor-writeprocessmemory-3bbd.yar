rule TTP_XOR_WriteProcessMemory_3bbd {
  strings:
    $key_3bbd = { 6c cf [2] 5e ed [2] 58 d8 [2] 76 d8 [2] 49 c4 }

  condition:
    any of them
}