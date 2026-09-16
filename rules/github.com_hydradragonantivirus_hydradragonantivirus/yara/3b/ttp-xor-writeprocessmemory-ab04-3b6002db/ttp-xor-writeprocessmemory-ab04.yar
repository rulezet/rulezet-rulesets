rule TTP_XOR_WriteProcessMemory_ab04 {
  strings:
    $key_ab04 = { fc 76 [2] ce 54 [2] c8 61 [2] e6 61 [2] d9 7d }

  condition:
    any of them
}