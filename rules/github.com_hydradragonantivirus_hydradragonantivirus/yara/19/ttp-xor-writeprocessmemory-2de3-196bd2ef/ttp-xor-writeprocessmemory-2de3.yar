rule TTP_XOR_WriteProcessMemory_2de3 {
  strings:
    $key_2de3 = { 7a 91 [2] 48 b3 [2] 4e 86 [2] 60 86 [2] 5f 9a }

  condition:
    any of them
}