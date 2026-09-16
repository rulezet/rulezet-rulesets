rule TTP_XOR_WriteProcessMemory_ab70 {
  strings:
    $key_ab70 = { fc 02 [2] ce 20 [2] c8 15 [2] e6 15 [2] d9 09 }

  condition:
    any of them
}