rule TTP_XOR_WriteProcessMemory_8cbd {
  strings:
    $key_8cbd = { db cf [2] e9 ed [2] ef d8 [2] c1 d8 [2] fe c4 }

  condition:
    any of them
}