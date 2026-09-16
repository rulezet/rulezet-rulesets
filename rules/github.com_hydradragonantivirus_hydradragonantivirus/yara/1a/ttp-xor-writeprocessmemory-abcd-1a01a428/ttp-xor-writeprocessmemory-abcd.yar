rule TTP_XOR_WriteProcessMemory_abcd {
  strings:
    $key_abcd = { fc bf [2] ce 9d [2] c8 a8 [2] e6 a8 [2] d9 b4 }

  condition:
    any of them
}