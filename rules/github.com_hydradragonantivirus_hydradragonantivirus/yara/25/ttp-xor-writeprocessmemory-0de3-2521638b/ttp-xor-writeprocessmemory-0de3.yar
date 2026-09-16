rule TTP_XOR_WriteProcessMemory_0de3 {
  strings:
    $key_0de3 = { 5a 91 [2] 68 b3 [2] 6e 86 [2] 40 86 [2] 7f 9a }

  condition:
    any of them
}