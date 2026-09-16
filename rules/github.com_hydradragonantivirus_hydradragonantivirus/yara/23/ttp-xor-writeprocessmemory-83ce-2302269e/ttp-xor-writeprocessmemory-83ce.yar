rule TTP_XOR_WriteProcessMemory_83ce {
  strings:
    $key_83ce = { d4 bc [2] e6 9e [2] e0 ab [2] ce ab [2] f1 b7 }

  condition:
    any of them
}