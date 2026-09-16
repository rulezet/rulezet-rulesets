rule TTP_XOR_WriteProcessMemory_ab15 {
  strings:
    $key_ab15 = { fc 67 [2] ce 45 [2] c8 70 [2] e6 70 [2] d9 6c }

  condition:
    any of them
}