rule TTP_XOR_WriteProcessMemory_edc6 {
  strings:
    $key_edc6 = { ba b4 [2] 88 96 [2] 8e a3 [2] a0 a3 [2] 9f bf }

  condition:
    any of them
}