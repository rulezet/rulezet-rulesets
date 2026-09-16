rule TTP_XOR_WriteProcessMemory_bcbd {
  strings:
    $key_bcbd = { eb cf [2] d9 ed [2] df d8 [2] f1 d8 [2] ce c4 }

  condition:
    any of them
}