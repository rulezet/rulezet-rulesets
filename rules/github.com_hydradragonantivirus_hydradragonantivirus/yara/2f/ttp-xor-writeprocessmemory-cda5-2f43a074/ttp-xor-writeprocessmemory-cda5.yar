rule TTP_XOR_WriteProcessMemory_cda5 {
  strings:
    $key_cda5 = { 9a d7 [2] a8 f5 [2] ae c0 [2] 80 c0 [2] bf dc }

  condition:
    any of them
}