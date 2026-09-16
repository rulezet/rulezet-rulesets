rule TTP_XOR_WriteProcessMemory_9793 {
  strings:
    $key_9793 = { c0 e1 [2] f2 c3 [2] f4 f6 [2] da f6 [2] e5 ea }

  condition:
    any of them
}