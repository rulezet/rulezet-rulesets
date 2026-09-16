rule TTP_XOR_WriteProcessMemory_3134 {
  strings:
    $key_3134 = { 66 46 [2] 54 64 [2] 52 51 [2] 7c 51 [2] 43 4d }

  condition:
    any of them
}