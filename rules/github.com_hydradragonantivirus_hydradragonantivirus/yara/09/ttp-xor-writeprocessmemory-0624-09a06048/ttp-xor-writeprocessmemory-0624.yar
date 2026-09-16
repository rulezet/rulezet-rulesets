rule TTP_XOR_WriteProcessMemory_0624 {
  strings:
    $key_0624 = { 51 56 [2] 63 74 [2] 65 41 [2] 4b 41 [2] 74 5d }

  condition:
    any of them
}