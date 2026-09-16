rule TTP_XOR_WriteProcessMemory_ab23 {
  strings:
    $key_ab23 = { fc 51 [2] ce 73 [2] c8 46 [2] e6 46 [2] d9 5a }

  condition:
    any of them
}