rule TTP_XOR_WriteProcessMemory_b062 {
  strings:
    $key_b062 = { e7 10 [2] d5 32 [2] d3 07 [2] fd 07 [2] c2 1b }

  condition:
    any of them
}