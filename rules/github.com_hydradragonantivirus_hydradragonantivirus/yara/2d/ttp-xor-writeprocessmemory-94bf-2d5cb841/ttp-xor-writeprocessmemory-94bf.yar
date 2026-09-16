rule TTP_XOR_WriteProcessMemory_94bf {
  strings:
    $key_94bf = { c3 cd [2] f1 ef [2] f7 da [2] d9 da [2] e6 c6 }

  condition:
    any of them
}