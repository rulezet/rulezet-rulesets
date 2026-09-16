rule TTP_XOR_WriteProcessMemory_eda3 {
  strings:
    $key_eda3 = { ba d1 [2] 88 f3 [2] 8e c6 [2] a0 c6 [2] 9f da }

  condition:
    any of them
}