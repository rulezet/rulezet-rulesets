rule TTP_XOR_WriteProcessMemory_e234 {
  strings:
    $key_e234 = { b5 46 [2] 87 64 [2] 81 51 [2] af 51 [2] 90 4d }

  condition:
    any of them
}