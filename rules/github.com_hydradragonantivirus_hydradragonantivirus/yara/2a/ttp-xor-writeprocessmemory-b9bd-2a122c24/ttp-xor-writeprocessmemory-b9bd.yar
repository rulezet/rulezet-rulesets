rule TTP_XOR_WriteProcessMemory_b9bd {
  strings:
    $key_b9bd = { ee cf [2] dc ed [2] da d8 [2] f4 d8 [2] cb c4 }

  condition:
    any of them
}