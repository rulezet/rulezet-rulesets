rule TTP_XOR_WriteProcessMemory_3717 {
  strings:
    $key_3717 = { 60 65 [2] 52 47 [2] 54 72 [2] 7a 72 [2] 45 6e }

  condition:
    any of them
}