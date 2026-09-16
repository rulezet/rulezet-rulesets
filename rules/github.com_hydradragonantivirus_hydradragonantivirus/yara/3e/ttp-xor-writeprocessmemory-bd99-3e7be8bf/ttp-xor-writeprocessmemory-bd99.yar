rule TTP_XOR_WriteProcessMemory_bd99 {
  strings:
    $key_bd99 = { ea eb [2] d8 c9 [2] de fc [2] f0 fc [2] cf e0 }

  condition:
    any of them
}