rule TTP_XOR_WriteProcessMemory_04b3 {
  strings:
    $key_04b3 = { 53 c1 [2] 61 e3 [2] 67 d6 [2] 49 d6 [2] 76 ca }

  condition:
    any of them
}