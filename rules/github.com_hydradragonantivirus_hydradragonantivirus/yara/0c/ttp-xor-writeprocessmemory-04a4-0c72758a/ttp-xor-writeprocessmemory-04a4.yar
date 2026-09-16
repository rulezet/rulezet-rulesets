rule TTP_XOR_WriteProcessMemory_04a4 {
  strings:
    $key_04a4 = { 53 d6 [2] 61 f4 [2] 67 c1 [2] 49 c1 [2] 76 dd }

  condition:
    any of them
}