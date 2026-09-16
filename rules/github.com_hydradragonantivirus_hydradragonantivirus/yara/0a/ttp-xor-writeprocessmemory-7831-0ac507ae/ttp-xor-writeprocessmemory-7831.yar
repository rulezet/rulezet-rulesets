rule TTP_XOR_WriteProcessMemory_7831 {
  strings:
    $key_7831 = { 2f 43 [2] 1d 61 [2] 1b 54 [2] 35 54 [2] 0a 48 }

  condition:
    any of them
}