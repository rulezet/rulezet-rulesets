rule TTP_XOR_WriteProcessMemory_2ce3 {
  strings:
    $key_2ce3 = { 7b 91 [2] 49 b3 [2] 4f 86 [2] 61 86 [2] 5e 9a }

  condition:
    any of them
}