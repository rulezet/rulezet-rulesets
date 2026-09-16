rule TTP_XOR_WriteProcessMemory_cb52 {
  strings:
    $key_cb52 = { 9c 20 [2] ae 02 [2] a8 37 [2] 86 37 [2] b9 2b }

  condition:
    any of them
}