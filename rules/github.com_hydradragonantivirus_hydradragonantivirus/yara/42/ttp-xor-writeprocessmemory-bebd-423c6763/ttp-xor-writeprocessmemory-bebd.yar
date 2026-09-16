rule TTP_XOR_WriteProcessMemory_bebd {
  strings:
    $key_bebd = { e9 cf [2] db ed [2] dd d8 [2] f3 d8 [2] cc c4 }

  condition:
    any of them
}