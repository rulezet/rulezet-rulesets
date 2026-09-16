rule TTP_XOR_WriteProcessMemory_97bf {
  strings:
    $key_97bf = { c0 cd [2] f2 ef [2] f4 da [2] da da [2] e5 c6 }

  condition:
    any of them
}