rule TTP_XOR_WriteProcessMemory_b264 {
  strings:
    $key_b264 = { e5 16 [2] d7 34 [2] d1 01 [2] ff 01 [2] c0 1d }

  condition:
    any of them
}