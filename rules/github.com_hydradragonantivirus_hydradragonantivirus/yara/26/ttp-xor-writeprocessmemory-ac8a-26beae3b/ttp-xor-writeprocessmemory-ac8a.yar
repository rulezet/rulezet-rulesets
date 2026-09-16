rule TTP_XOR_WriteProcessMemory_ac8a {
  strings:
    $key_ac8a = { fb f8 [2] c9 da [2] cf ef [2] e1 ef [2] de f3 }

  condition:
    any of them
}