rule TTP_XOR_WriteProcessMemory_4ce3 {
  strings:
    $key_4ce3 = { 1b 91 [2] 29 b3 [2] 2f 86 [2] 01 86 [2] 3e 9a }

  condition:
    any of them
}