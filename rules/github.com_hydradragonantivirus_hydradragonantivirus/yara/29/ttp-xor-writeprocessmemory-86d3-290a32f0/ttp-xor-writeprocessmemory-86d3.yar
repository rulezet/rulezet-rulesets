rule TTP_XOR_WriteProcessMemory_86d3 {
  strings:
    $key_86d3 = { d1 a1 [2] e3 83 [2] e5 b6 [2] cb b6 [2] f4 aa }

  condition:
    any of them
}