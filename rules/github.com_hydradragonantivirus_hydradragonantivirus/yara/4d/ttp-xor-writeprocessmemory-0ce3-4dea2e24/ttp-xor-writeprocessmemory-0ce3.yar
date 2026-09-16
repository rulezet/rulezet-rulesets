rule TTP_XOR_WriteProcessMemory_0ce3 {
  strings:
    $key_0ce3 = { 5b 91 [2] 69 b3 [2] 6f 86 [2] 41 86 [2] 7e 9a }

  condition:
    any of them
}