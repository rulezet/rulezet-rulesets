rule TTP_XOR_WriteProcessMemory_eda6 {
  strings:
    $key_eda6 = { ba d4 [2] 88 f6 [2] 8e c3 [2] a0 c3 [2] 9f df }

  condition:
    any of them
}