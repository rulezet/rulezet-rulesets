rule TTP_XOR_WriteProcessMemory_cb67 {
  strings:
    $key_cb67 = { 9c 15 [2] ae 37 [2] a8 02 [2] 86 02 [2] b9 1e }

  condition:
    any of them
}