rule TTP_XOR_WriteProcessMemory_babd {
  strings:
    $key_babd = { ed cf [2] df ed [2] d9 d8 [2] f7 d8 [2] c8 c4 }

  condition:
    any of them
}