rule TTP_XOR_WriteProcessMemory_24e3 {
  strings:
    $key_24e3 = { 73 91 [2] 41 b3 [2] 47 86 [2] 69 86 [2] 56 9a }

  condition:
    any of them
}