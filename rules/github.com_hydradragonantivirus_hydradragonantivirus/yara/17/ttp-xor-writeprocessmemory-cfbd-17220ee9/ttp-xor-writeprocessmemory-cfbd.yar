rule TTP_XOR_WriteProcessMemory_cfbd {
  strings:
    $key_cfbd = { 98 cf [2] aa ed [2] ac d8 [2] 82 d8 [2] bd c4 }

  condition:
    any of them
}