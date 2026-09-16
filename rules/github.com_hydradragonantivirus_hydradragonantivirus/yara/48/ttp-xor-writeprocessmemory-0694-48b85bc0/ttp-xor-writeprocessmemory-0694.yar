rule TTP_XOR_WriteProcessMemory_0694 {
  strings:
    $key_0694 = { 51 e6 [2] 63 c4 [2] 65 f1 [2] 4b f1 [2] 74 ed }

  condition:
    any of them
}