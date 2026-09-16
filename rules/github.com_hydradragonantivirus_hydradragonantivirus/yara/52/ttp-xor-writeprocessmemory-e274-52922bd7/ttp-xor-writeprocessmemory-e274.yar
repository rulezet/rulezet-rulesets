rule TTP_XOR_WriteProcessMemory_e274 {
  strings:
    $key_e274 = { b5 06 [2] 87 24 [2] 81 11 [2] af 11 [2] 90 0d }

  condition:
    any of them
}