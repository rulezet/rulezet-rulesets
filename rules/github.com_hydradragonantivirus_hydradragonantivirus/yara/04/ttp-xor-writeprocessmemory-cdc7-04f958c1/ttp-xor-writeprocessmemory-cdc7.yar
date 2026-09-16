rule TTP_XOR_WriteProcessMemory_cdc7 {
  strings:
    $key_cdc7 = { 9a b5 [2] a8 97 [2] ae a2 [2] 80 a2 [2] bf be }

  condition:
    any of them
}