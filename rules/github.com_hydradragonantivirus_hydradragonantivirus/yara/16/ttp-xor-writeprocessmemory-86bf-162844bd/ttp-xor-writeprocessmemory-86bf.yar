rule TTP_XOR_WriteProcessMemory_86bf {
  strings:
    $key_86bf = { d1 cd [2] e3 ef [2] e5 da [2] cb da [2] f4 c6 }

  condition:
    any of them
}