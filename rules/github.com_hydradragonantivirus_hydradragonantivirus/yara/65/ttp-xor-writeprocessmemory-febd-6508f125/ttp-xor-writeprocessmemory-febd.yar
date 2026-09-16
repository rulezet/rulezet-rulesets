rule TTP_XOR_WriteProcessMemory_febd {
  strings:
    $key_febd = { a9 cf [2] 9b ed [2] 9d d8 [2] b3 d8 [2] 8c c4 }

  condition:
    any of them
}