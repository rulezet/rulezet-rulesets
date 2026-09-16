rule TTP_XOR_WriteProcessMemory_2494 {
  strings:
    $key_2494 = { 73 e6 [2] 41 c4 [2] 47 f1 [2] 69 f1 [2] 56 ed }

  condition:
    any of them
}