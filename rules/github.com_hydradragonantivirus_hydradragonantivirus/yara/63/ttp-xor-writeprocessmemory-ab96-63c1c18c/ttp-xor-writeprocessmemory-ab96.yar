rule TTP_XOR_WriteProcessMemory_ab96 {
  strings:
    $key_ab96 = { fc e4 [2] ce c6 [2] c8 f3 [2] e6 f3 [2] d9 ef }

  condition:
    any of them
}