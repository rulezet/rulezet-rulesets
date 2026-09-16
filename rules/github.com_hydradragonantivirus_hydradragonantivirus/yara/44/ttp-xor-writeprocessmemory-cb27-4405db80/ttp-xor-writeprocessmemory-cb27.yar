rule TTP_XOR_WriteProcessMemory_cb27 {
  strings:
    $key_cb27 = { 9c 55 [2] ae 77 [2] a8 42 [2] 86 42 [2] b9 5e }

  condition:
    any of them
}