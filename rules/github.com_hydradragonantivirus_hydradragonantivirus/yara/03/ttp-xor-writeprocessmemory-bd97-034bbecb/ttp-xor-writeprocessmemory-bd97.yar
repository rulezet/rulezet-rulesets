rule TTP_XOR_WriteProcessMemory_bd97 {
  strings:
    $key_bd97 = { ea e5 [2] d8 c7 [2] de f2 [2] f0 f2 [2] cf ee }

  condition:
    any of them
}