rule TTP_XOR_WriteProcessMemory_cbe3 {
  strings:
    $key_cbe3 = { 9c 91 [2] ae b3 [2] a8 86 [2] 86 86 [2] b9 9a }

  condition:
    any of them
}