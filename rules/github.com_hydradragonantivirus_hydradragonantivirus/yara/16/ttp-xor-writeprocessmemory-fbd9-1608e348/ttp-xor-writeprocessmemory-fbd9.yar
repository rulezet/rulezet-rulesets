rule TTP_XOR_WriteProcessMemory_fbd9 {
  strings:
    $key_fbd9 = { ac ab [2] 9e 89 [2] 98 bc [2] b6 bc [2] 89 a0 }

  condition:
    any of them
}