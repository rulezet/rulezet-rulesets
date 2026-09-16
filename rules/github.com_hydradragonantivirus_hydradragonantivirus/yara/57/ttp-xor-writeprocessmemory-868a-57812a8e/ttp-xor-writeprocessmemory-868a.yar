rule TTP_XOR_WriteProcessMemory_868a {
  strings:
    $key_868a = { d1 f8 [2] e3 da [2] e5 ef [2] cb ef [2] f4 f3 }

  condition:
    any of them
}