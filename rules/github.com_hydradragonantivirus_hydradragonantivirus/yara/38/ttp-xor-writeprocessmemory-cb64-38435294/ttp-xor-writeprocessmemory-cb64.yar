rule TTP_XOR_WriteProcessMemory_cb64 {
  strings:
    $key_cb64 = { 9c 16 [2] ae 34 [2] a8 01 [2] 86 01 [2] b9 1d }

  condition:
    any of them
}