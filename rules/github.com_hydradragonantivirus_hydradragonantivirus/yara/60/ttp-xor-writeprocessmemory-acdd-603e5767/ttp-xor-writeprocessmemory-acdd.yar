rule TTP_XOR_WriteProcessMemory_acdd {
  strings:
    $key_acdd = { fb af [2] c9 8d [2] cf b8 [2] e1 b8 [2] de a4 }

  condition:
    any of them
}