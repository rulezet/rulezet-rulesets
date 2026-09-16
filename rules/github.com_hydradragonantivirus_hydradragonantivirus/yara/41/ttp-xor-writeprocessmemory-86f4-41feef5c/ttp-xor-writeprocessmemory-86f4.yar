rule TTP_XOR_WriteProcessMemory_86f4 {
  strings:
    $key_86f4 = { d1 86 [2] e3 a4 [2] e5 91 [2] cb 91 [2] f4 8d }

  condition:
    any of them
}