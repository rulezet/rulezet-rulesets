rule TTP_XOR_WriteProcessMemory_31e3 {
  strings:
    $key_31e3 = { 66 91 [2] 54 b3 [2] 52 86 [2] 7c 86 [2] 43 9a }

  condition:
    any of them
}