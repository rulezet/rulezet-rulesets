rule TTP_XOR_WriteProcessMemory_86d8 {
  strings:
    $key_86d8 = { d1 aa [2] e3 88 [2] e5 bd [2] cb bd [2] f4 a1 }

  condition:
    any of them
}