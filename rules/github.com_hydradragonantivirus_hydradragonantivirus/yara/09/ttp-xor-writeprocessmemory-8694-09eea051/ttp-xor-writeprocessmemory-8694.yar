rule TTP_XOR_WriteProcessMemory_8694 {
  strings:
    $key_8694 = { d1 e6 [2] e3 c4 [2] e5 f1 [2] cb f1 [2] f4 ed }

  condition:
    any of them
}