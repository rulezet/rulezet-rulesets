rule TTP_XOR_WriteProcessMemory_bbe3 {
  strings:
    $key_bbe3 = { ec 91 [2] de b3 [2] d8 86 [2] f6 86 [2] c9 9a }

  condition:
    any of them
}