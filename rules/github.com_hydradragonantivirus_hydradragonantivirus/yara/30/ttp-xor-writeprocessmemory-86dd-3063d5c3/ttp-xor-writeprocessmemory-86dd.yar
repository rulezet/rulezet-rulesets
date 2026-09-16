rule TTP_XOR_WriteProcessMemory_86dd {
  strings:
    $key_86dd = { d1 af [2] e3 8d [2] e5 b8 [2] cb b8 [2] f4 a4 }

  condition:
    any of them
}