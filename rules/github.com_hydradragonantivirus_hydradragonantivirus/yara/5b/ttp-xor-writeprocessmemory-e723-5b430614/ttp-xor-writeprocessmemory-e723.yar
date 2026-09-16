rule TTP_XOR_WriteProcessMemory_e723 {
  strings:
    $key_e723 = { b0 51 [2] 82 73 [2] 84 46 [2] aa 46 [2] 95 5a }

  condition:
    any of them
}