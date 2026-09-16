rule TTP_XOR_WriteProcessMemory_cb31 {
  strings:
    $key_cb31 = { 9c 43 [2] ae 61 [2] a8 54 [2] 86 54 [2] b9 48 }

  condition:
    any of them
}