rule TTP_XOR_WriteProcessMemory_94d3 {
  strings:
    $key_94d3 = { c3 a1 [2] f1 83 [2] f7 b6 [2] d9 b6 [2] e6 aa }

  condition:
    any of them
}