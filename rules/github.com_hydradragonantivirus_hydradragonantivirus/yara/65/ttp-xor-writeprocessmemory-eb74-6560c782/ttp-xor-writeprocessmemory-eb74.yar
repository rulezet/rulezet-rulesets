rule TTP_XOR_WriteProcessMemory_eb74 {
  strings:
    $key_eb74 = { bc 06 [2] 8e 24 [2] 88 11 [2] a6 11 [2] 99 0d }

  condition:
    any of them
}