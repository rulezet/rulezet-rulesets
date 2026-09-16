rule TTP_XOR_WriteProcessMemory_cb37 {
  strings:
    $key_cb37 = { 9c 45 [2] ae 67 [2] a8 52 [2] 86 52 [2] b9 4e }

  condition:
    any of them
}